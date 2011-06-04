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

#include "config.h"

#ifdef HAVE_PYTHON
#include <Python.h> /* defines _GNU_SOURCE */
#else
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#endif

#include <sqlite3.h>

#ifdef HAVE_PYTHON
#include "py.h"
#endif

#include "hgd.h"
#include "db.h"

uint8_t				 purge_finished_db = 1;
uint8_t				 purge_finished_fs = 1;
uint8_t				 clear_playlist_on_start = 0;
const char			*hgd_component = "playd";

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

#ifdef HAVE_PYTHON
	hgd_free_py();
#endif

	exit (!exit_ok);
}

void
hgd_play_track(struct hgd_playlist_item *t)
{
	int			status = 0, pid;
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
#ifdef HAVE_PYTHON
		hgd_execute_py_hook("pre_play");
#endif

		execlp("mplayer", "mplayer", "-really-quiet",
		    t->filename, (char *) NULL);

#ifdef HAVE_PYTHON
		hgd_execute_py_hook("post_play");
#endif


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
hgd_play_loop(void)
{
	struct hgd_playlist_item	 track;

	/* forever play songs */
	DPRINTF(HGD_D_DEBUG, "Starting play loop");
	while (!dying) {
		memset(&track, 0, sizeof(track));

		if (hgd_get_next_track(&track) == HGD_FAIL)
			hgd_exit_nicely();

		if (track.filename != NULL) {
			DPRINTF(HGD_D_DEBUG, "next track is: '%s'",
			    track.filename);

			hgd_clear_votes();
			hgd_play_track(&track);
		} else {
			DPRINTF(HGD_D_DEBUG, "no tracks to play");
#ifdef HAVE_PYTHON
			hgd_execute_py_hook("nothing_to_play");
#endif
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
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 */
	config_t		 cfg, *cf;
	long long int		 tmp_hgd_debug;
	int			 tmp_purge_fin_fs, tmp_purge_fin_db;
	char			*tmp_state_path;
#ifdef HAVE_PYTHON
	char			*tmp_py_dir;
#endif
	struct stat		 st;

	cf = &cfg;
	config_init(cf);

	while (*config_locations != NULL) {

		/* Try and open usr config */
		DPRINTF(HGD_D_INFO, "Trying to read config from: %s",
		    *config_locations);

		/* XXX: can be removed when deb get new libconfig */
		if ( stat (*config_locations, &st) < 0 ) {
			DPRINTF(HGD_D_INFO, "Could not stat %s",
			    *config_locations);
			config_locations--;
			continue;
		}

		if (config_read_file(cf, *config_locations)) {
			break;
		} else {
#if 1
			DPRINTF(HGD_D_ERROR, "%s (line: %d)",
			    config_error_text(cf), config_error_line(cf));
#else
			/*
			 * XXX: we can use this verion when debian
			 * get new libconfig
			 */
                        if (config_error_type (cf) == CONFIG_ERR_FILE_IO) {
				DPRINTF(HGD_D_INFO, "%s (line: %d)",
				    config_error_text(cf),
				    config_error_line(cf));
			} else {
				DPRINTF(HGD_D_ERROR, "%s (line: %d)",
				    config_error_text(cf),
				    config_error_line(cf));
			}
#endif
			config_locations--;
		}
	}

	if (*config_locations == NULL) {
		config_destroy(cf);
		return (HGD_OK);
	}

	/* -d */
	if (config_lookup_string(cf, "state_path",
	    (const char **) &tmp_state_path)) {
		free(state_path);
		state_path = xstrdup(tmp_state_path);
		DPRINTF(HGD_D_DEBUG, "Set hgd state path to '%s'", state_path);
	}

	/* -p */
	if (config_lookup_bool(cf, "playd.purge_fs", &tmp_purge_fin_fs)) {
		purge_finished_fs = tmp_purge_fin_fs;
		DPRINTF(HGD_D_DEBUG,
		    "fs purging is %s", (purge_finished_fs ? "on" : "off"));
	}

#ifdef HAVE_PYTHON
	/* -P */
	if (config_lookup_string(cf, "py_plugins.script_path",
	    (const char **) &tmp_py_dir)) {
		if (hgd_py_plugin_dir != NULL)
			free(hgd_py_plugin_dir);

		hgd_py_plugin_dir = strdup(tmp_py_dir);
		DPRINTF(HGD_D_DEBUG,"Setting python path to %s",
		    hgd_py_plugin_dir);
	}
#endif


	/* -p */
	if (config_lookup_bool(cf, "playd.purge_db", &tmp_purge_fin_db)) {
		purge_finished_db = tmp_purge_fin_db;
		DPRINTF(HGD_D_DEBUG,
		    "db purging is %s", (purge_finished_db ? "on" : "off"));
	}

	/* -x */
	if (config_lookup_int64(cf, "debug", &tmp_hgd_debug)) {
		hgd_debug = tmp_hgd_debug;
		DPRINTF(HGD_D_DEBUG, "Set debug level to %d", hgd_debug);
	}

	config_destroy(cf);
#endif
	return (HGD_OK);
}

void
hgd_usage(void)
{
	printf("usage: hgd-netd <options>\n");
#ifdef HAVE_LIBCONFIG
	printf("  -c	Path to a config file to use\n");
#endif
	printf("  -C	Clear playlist on startup\n");
	printf("  -d	Set hgd state directory\n");
	printf("  -h	Show this message and exit\n");
	printf("  -p	Don't purge finished tracks from filesystem\n");
#ifdef HAVE_PYTHON
	printf("  -P	Location of user scripts\n");
#endif
	printf("  -q	Don't purge finished tracks in database\n");
	printf("  -v	Show version and exit\n");
	printf("  -x	Set debug level (0-3)\n");
}

#if 0
/* eventually remove, this was just us getting to grips with python */
void
py_test()
{
	PyObject		*mod, *func, *ret, *args = NULL, *arg1;

	Py_Initialize();

	mod = PyImport_ImportModule("os");
	if (mod == NULL) {
		PyErr_Print();
		DPRINTF(HGD_D_ERROR, "failed to import");
	}

	func = PyObject_GetAttrString(mod, "getenv");
	if (func && PyCallable_Check(func)) {
		args = PyTuple_New(1);
		arg1 = PyString_FromString("HOME");
		PyTuple_SetItem(args, 0, arg1);
	} else {
		PyErr_Print();
		DPRINTF(HGD_D_ERROR, "failed find func");
	}

	ret = PyObject_CallObject(func, args);
	if (ret == NULL) {
		PyErr_Print();
		DPRINTF(HGD_D_ERROR, "call failed");
	}

	printf("HOME = %s\n", PyString_AsString(ret));

	Py_DECREF(ret);
	Py_DECREF(func);
	Py_DECREF(mod);

}
#endif

int
main(int argc, char **argv)
{
	char			 ch, *env_tmp;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	config_path[0] = NULL;

	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_SERV_CFG);

	env_tmp =  getenv("XDG_CONFIG_HOME");
	if (config_path == NULL) {
		xasprintf(&config_path[2], "%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR HGD_SERV_CFG );
	} else {
		xasprintf(&config_path[2], "%s%s", env_tmp , "/hgd" HGD_SERV_CFG);

	}

	hgd_register_sig_handlers();
	state_path = xstrdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "c:Cd:hpP:qvx:")) != -1) {
		switch (ch) {
		case 'c':
			if (num_config < 3) {
				num_config++;
				DPRINTF(HGD_D_DEBUG, "added config %d %s",
				    num_config, optarg);
				config_path[num_config] = optarg;
			} else {
				DPRINTF(HGD_D_WARN,
				    "Too many config files specified");
				hgd_exit_nicely();
			}
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG,
			    "set debug level to %d", hgd_debug);
			break;
		default:
			break; /* catch badness in next getopt */
		};
	}

	hgd_read_config(config_path + num_config);

	RESET_GETOPT();

	DPRINTF(HGD_D_DEBUG, "Parsing options");
	while ((ch = getopt(argc, argv, "c:Cd:hpP:qvx:")) != -1) {
		switch (ch) {
		case 'c':
			break; /* already handled */
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
#ifdef HAVE_PYTHON
		case 'P':
			DPRINTF(HGD_D_DEBUG, "Setting python plugin dir");
			if (hgd_py_plugin_dir != NULL)
				free(hgd_py_plugin_dir);
			hgd_py_plugin_dir = xstrdup(optarg);
			break;
#endif
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
			DPRINTF(HGD_D_DEBUG, "set debug to %d", atoi(optarg));
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			break; /* already set but over-rideable */
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

	if (hgd_init_playstate() != HGD_OK)
		hgd_exit_nicely();

	if (clear_playlist_on_start) {
		if (hgd_clear_playlist() != HGD_OK)
			hgd_exit_nicely();
	}

	/* do the Python dance */
#ifdef HAVE_PYTHON
	if (hgd_embed_py(1) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise Python");
		hgd_exit_nicely();
	}
#endif

	/* start */
	hgd_play_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
