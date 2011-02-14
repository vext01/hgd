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
	if (hgd_dir)
		free(hgd_dir);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	exit (!exit_ok);
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, pid;
	char			*pid_path;
	FILE			*pid_file;

	DPRINTF(HGD_D_INFO, "Playing '%s' for '%s'", t->filename, t->user);
	if (hgd_mark_playing(t->id) == -1)
		hgd_exit_nicely();

	pid = fork();
	if (!pid) {
		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-really-quiet",
		    t->filename, (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		DPRINTF(HGD_D_ERROR, "execlp() failed");
		hgd_exit_nicely();
	} else {
		/* we will write away child pid */
		xasprintf(&pid_path, "%s/%s", hgd_dir, HGD_MPLAYER_PID_NAME);

		pid_file = fopen(pid_path, "w");
		if (pid_file == NULL) {
			DPRINTF(HGD_D_ERROR, "Can't open '%s'", pid_path);
			free(pid_path);
			hgd_exit_nicely();
		}

		fprintf(pid_file, "%d", pid);
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

	if (hgd_mark_finished(t->id, purge_finished_db) == -1)
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

		if (hgd_get_next_track(&track) == -1) {
			hgd_exit_nicely();
		}

		if (track.filename != NULL) {
			DPRINTF(HGD_D_DEBUG, "next track is: '%s'",
			    track.filename);
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

/* NOTE! -c is reserved for 'config file path' */
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

	hgd_register_sig_handlers();
	hgd_dir = strdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options");
	while ((ch = getopt(argc, argv, "Cd:hpqvx:")) != -1) {
		switch (ch) {
		case 'C':
			clear_playlist_on_start = 1;
			DPRINTF(HGD_D_DEBUG, "will clear playlist '%s'",
			    hgd_dir);
			break;
		case 'd':
			free(hgd_dir);
			hgd_dir = strdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set hgd dir to '%s'", hgd_dir);
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

		argc -= optind;
		argv += optind;
	}

	xasprintf(&db_path, "%s/%s", hgd_dir, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", hgd_dir, HGD_FILESTORE_NAME);
	hgd_mk_state_dir();

	db = hgd_open_db(db_path);
	if (db == NULL)
		hgd_exit_nicely();

	hgd_init_playstate();

	if (clear_playlist_on_start)
		hgd_clear_playlist();

	/* start */
	hgd_play_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
