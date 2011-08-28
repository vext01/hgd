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
#include "cfg.h"

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
#include <signal.h>

#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#endif

#include <sqlite3.h>

#ifdef HAVE_PYTHON
#include "py.h"
#endif

#include "hgd.h"
#include "db.h"
#include "mplayer.h"

const char			*hgd_component = "hgd-playd";

uint8_t				 purge_finished_db = 1;
uint8_t				 purge_finished_fs = 1;
uint8_t				 clear_playlist_on_start = 0;
int				 background = 1;

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-playd was interrupted or crashed\n");

	hgd_free_mplayer_globals();
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

	/* before syslog goes down */
	if (restarting)
		hgd_restart_myself();

	HGD_CLOSE_SYSLOG();

	exit (!exit_ok);
}

void
hgd_play_loop(void)
{
	struct hgd_playlist_item	 track;

	/* forever play songs */
	DPRINTF(HGD_D_DEBUG, "Starting play loop");
	while ((!dying) && (!restarting)) {
		memset(&track, 0, sizeof(track));

		if (hgd_get_next_track(&track) == HGD_FAIL)
			hgd_exit_nicely();

		if (track.filename != NULL) {
			DPRINTF(HGD_D_DEBUG, "next track is: '%s'",
			    track.filename);

			hgd_clear_votes();
			hgd_play_track(&track, purge_finished_fs, purge_finished_db);
		} else {
			DPRINTF(HGD_D_DEBUG, "no tracks to play");
#ifdef HAVE_PYTHON
			hgd_execute_py_hook("nothing_to_play");
#endif
			sleep(1);
		}
		hgd_free_playlist_item(&track);
	}
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

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		return (HGD_OK);
	}
	
	hgd_cfg_daemonise(cf, "playd", &background);
	hgd_cfg_statepath(cf, &state_path);
	hgd_cfg_playd_purgefs(cf, &purge_finished_fs);
#ifdef HAVE_PYTHON
	hgd_cfg_pluginpath(cf, &hgd_py_plugin_dir);
#endif
	hgd_cfg_playd_purgedb(cf, &purge_finished_db);
	hgd_cfg_debug(cf, "playd", &hgd_debug);

	config_destroy(cf);
#endif
	return (HGD_OK);
}

void
hgd_usage(void)
{
	printf("usage: hgd-netd <options>\n");
	printf("    -B			Do not daemonise, run in foreground\n");
#ifdef HAVE_LIBCONFIG
	printf("    -c <path>		Path to a config file to use\n");
#endif
	printf("    -C			Clear playlist on startup\n");
	printf("    -d <path>		Set hgd state directory\n");
	printf("    -h			Show this message and exit\n");
	printf("    -p			Don't purge finished tracks from filesystem\n");
#ifdef HAVE_PYTHON
	printf("    -P <path>		Location of Python plugins\n");
#endif
	printf("    -q			Don't purge finished tracks in database\n");
	printf("    -v			Show version and exit\n");
	printf("    -x <level>		Set debug level (0-3)\n");
}

int
main(int argc, char **argv)
{
	char			 ch, *xdg_config_home;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	/* early as possible */
	HGD_INIT_SYSLOG_DAEMON();

	config_path[0] = NULL;

	xasprintf(&config_path[1], "%s", HGD_GLOBAL_CFG_DIR HGD_SERV_CFG);

	xdg_config_home =  getenv("XDG_CONFIG_HOME");
	if (xdg_config_home == NULL) {
		xasprintf(&config_path[2], "%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR HGD_SERV_CFG );
	} else {
		xasprintf(&config_path[2],
		    "%s%s", xdg_config_home , "/hgd" HGD_SERV_CFG);
	}

	hgd_register_sig_handlers();
	state_path = xstrdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "Bc:Cd:hpP:qvx:")) != -1) {
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

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}

	RESET_GETOPT();

	if (hgd_cache_exec_context(argv) != HGD_OK)
		hgd_exit_nicely();

	DPRINTF(HGD_D_DEBUG, "Parsing options");
	while ((ch = getopt(argc, argv, "Bc:Cd:hpP:qvx:")) != -1) {
		switch (ch) {
		case 'B':
			background = 0;
			DPRINTF(HGD_D_DEBUG, "Not \"backgrounding\" daemon.");
			break;
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
	hgd_init_mplayer_globals();

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
	if (background) hgd_daemonise();
	hgd_play_loop();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
