/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
 * Copyright (c) 2011, Martin Ellis <ellism88@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <libconfig.h>

#include <sqlite3.h>

#include "hgd.h"
#include "db.h"

uint8_t				 purge_finished_db = 1;
uint8_t				 purge_finished_fs = 1;
uint8_t				 clear_playlist_on_start = 0;

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-playd was interrupted or crashed\n");

	if (db)
		sqlite3_close(db);
	if (state_path)
		free(state_path);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	exit (!exit_ok);
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, pid, song_id;
	char			*pid_path;
	FILE			*pid_file;
	struct flock		fl;

	fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
	fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
	fl.l_start  = 0;        /* Offset from l_whence         */
	fl.l_len    = 0;        /* length, 0 = to EOF           */
	fl.l_pid    = getpid(); /* our PID                      */

	DPRINTF(HGD_D_INFO, "Playing '%s' for '%s'", t->filename, t->user);
	if (hgd_mark_playing(t->id) == HGD_FAIL)
		hgd_exit_nicely();

	/* we will write away child pid */
	xasprintf(&pid_path, "%s/%s", state_path, HGD_MPLAYER_PID_NAME);

	pid_file = fopen(pid_path, "w");
	if (pid_file == NULL) {
		DPRINTF(HGD_D_ERROR, "Can't open '%s'", pid_path);
		free(pid_path);
		hgd_exit_nicely();
	}

	if (fcntl(fileno(pid_file), F_SETLKW, &fl) == -1) {
		DPRINTF(HGD_D_ERROR, "failed to get lock on pid file");
		hgd_exit_nicely();
	}

	if (chmod(pid_path, S_IRUSR | S_IWUSR) != 0)
		DPRINTF(HGD_D_WARN, "Can't secure mplayer pid file");

	pid = fork();
	if (!pid) {
		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-really-quiet",
		    t->filename, (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		DPRINTF(HGD_D_ERROR, "execlp() failed");
		hgd_exit_nicely();
	} else {
		fprintf(pid_file, "%d\n%d", pid, t->id);

		fl.l_type = F_UNLCK;  /* set to unlock same region */

		if (fcntl(fileno(pid_file), F_SETLK, &fl) == -1) {
			DPRINTF(HGD_D_ERROR, "failed to get lock on pid file");
			hgd_exit_nicely();
		}

		fclose(pid_file);
		wait(&status);

		/* unlink mplayer pid path */
		DPRINTF(HGD_D_DEBUG, "Deleting mplayer pid file");
		if (unlink(pid_path) < 0) {
			DPRINTF(HGD_D_WARN, "Can't unlink '%s'", pid_path);
		}
		free(pid_path);

		/* unlink media */
		if ((purge_finished_fs) && (unlink(t->filename) < 0)) {
			DPRINTF(HGD_D_DEBUG,
			    "Deleting finished: %s", t->filename);
			DPRINTF(HGD_D_WARN, "Can't unlink '%s'", pid_path);
		}
	}

	DPRINTF(HGD_D_DEBUG, "Finished playing (exit %d)", status);

	if (hgd_mark_finished(t->id, purge_finished_db) == HGD_FAIL)
		DPRINTF(HGD_D_WARN,
		    "Could not purge/mark finished -- trying to continue");
}

void
hgd_play_loop()
{
	struct hgd_playlist_item	 track;

	/* forever play songs */
	DPRINTF(HGD_D_DEBUG, "Starting play loop");
	while (!dying) {
		memset(&track, 0, sizeof(track));

		if (hgd_get_next_track(&track) == HGD_FAIL) {
			hgd_exit_nicely();
		}

		if (track.filename != NULL) {
			DPRINTF(HGD_D_DEBUG, "next track is: '%s'",
			    track.filename);
			/* XXX: Should we check the return val of this? */
			hgd_clear_votes();
			hgd_play_track(&track);
		} else {
			DPRINTF(HGD_D_DEBUG, "no tracks to play");
			sleep(1);
		}
		hgd_free_playlist_item(&track);
	}

	if (dying)
		hgd_exit_nicely();
}

int
hgd_read_config(char **config_locations)
{
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 */
	config_t 		 cfg, *cf;
	long int		 dont_fork = dont_fork;
	long long int		 tmp_hgd_debug;
	int			 tmp_purge_fin_fs, tmp_purge_fin_db;

	cf = &cfg;
	config_init(cf);

	while (*config_locations != NULL) {
		/* Try and open usr config */
		DPRINTF(HGD_D_ERROR, "TRYING TO READ CONFIG FROM - %s\n",
		    *config_locations);
		if (config_read_file(cf, *config_locations)) {
			break;
		} else {
			DPRINTF(HGD_D_ERROR, "%d - %s\n",
			    config_error_line(cf),
			    config_error_text(cf));

			config_destroy(cf);
			config_locations--;
		}
	}

	DPRINTF(HGD_D_DEBUG, "DONE");

	if (*config_locations == NULL) {
		return (HGD_OK);
	}

	/* -d */
	if (config_lookup_string(cf, "files", (const char**)&state_path)) {
		/* XXX: not sure if this strdup is needed */
		state_path = xstrdup(state_path);
		DPRINTF(HGD_D_DEBUG, "Set hgd dir to '%s'", state_path);
	}


	/* -p */
	if (config_lookup_bool(cf, "playd.purge_fs", &tmp_purge_fin_fs)) {
		purge_finished_fs = tmp_purge_fin_fs;
		DPRINTF(HGD_D_DEBUG,
		    "purgin is %s", (purge_finished_fs ? "on" : "off"));
	}

	/* -p */
	if (config_lookup_bool(cf, "playd.purge_db", &tmp_purge_fin_db)) {
		purge_finished_db = tmp_purge_fin_db;
		DPRINTF(HGD_D_DEBUG,
		    "purgin is %s", (purge_finished_db ? "on" : "off"));
	}

	/* XXX -x */
	if (config_lookup_int64(cf, "debug", &tmp_hgd_debug)) {
		hgd_debug = tmp_hgd_debug;
		DPRINTF(HGD_D_DEBUG, "Set debug level to %d", hgd_debug);
	}

	/* XXX add "config_destroy(cf);" to cleanup */
	return (HGD_OK);
}

void
hgd_usage()
{
	printf("usage: hgd-netd <options>\n");
	printf("  -C	Clear playlist on startup\n");
	printf("  -d	Set hgd state directory\n");
	printf("  -h	Show this message and exit\n");
	printf("  -p	Don't purge finished tracks from filesystem\n");
	printf("  -q	Don't purge finished tracks in database\n");
	printf("  -v	Show version and exit\n");
	printf("  -x	Set debug level (0-3)\n");
}

int
main(int argc, char **argv)
{
	char			 ch;
	char			*config_path[4] = {NULL,NULL,NULL,NULL};
	int			 num_config = 2;

	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_SERV_CFG );
	xasprintf(&config_path[2], "%s%s", getenv("HOME"),
	    HGD_USR_CFG_DIR HGD_SERV_CFG );

	hgd_register_sig_handlers();
	state_path = xstrdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "Cd:hpqvx:")) != -1) {
		switch (ch) {
		case 'c':
			num_config++;
			DPRINTF(HGD_D_DEBUG, "added config %d %s", num_config,
			    optarg);
			config_path[num_config] = optarg;
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG,
			    "set debug level to %d", hgd_debug);
			break;
		default:
			break;
		};
	}

	hgd_read_config(config_path + num_config);

	RESET_GETOPT();

	DPRINTF(HGD_D_DEBUG, "Parsing options");
	while ((ch = getopt(argc, argv, "Cd:hpqvx:")) != -1) {
		switch (ch) {
		case 'C':
			clear_playlist_on_start = 1;
			DPRINTF(HGD_D_DEBUG, "will clear playlist '%s'",
			    state_path);
			break;
		case 'd':
			free(state_path);
			state_path = xstrdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set hgd dir to '%s'", state_path);
			break;
		case 'p':
			DPRINTF(HGD_D_DEBUG, "No purging from fs");
			purge_finished_fs = 0;
			break;
		case 'q':
			DPRINTF(HGD_D_DEBUG, "No purging from db");
			purge_finished_db = 0;
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG,
			    "set debug level to %d", hgd_debug);
			break;
		case 'h':
		default:
			hgd_usage();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		};
	}

	argc -= optind;
	argv += optind;

	xasprintf(&db_path, "%s/%s", state_path, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", state_path, HGD_FILESTORE_NAME);

	umask(~S_IRWXU);
	hgd_mk_state_dir();

	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	/* XXX: Should we check the return state of this? */
	hgd_init_playstate();

	if (clear_playlist_on_start)
		/* XXX: Should we check the return state of this? */
		hgd_clear_playlist();

	/* start */
	hgd_play_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
