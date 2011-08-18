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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#endif
#include <sqlite3.h>
#include <openssl/rand.h>

#include "hgd.h"
#include "db.h"
#include "mplayer.h"

const char			*hgd_component = "hgd-admin";

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

	hgd_free_mplayer_globals();
	if (db)
		sqlite3_close(db);
	if (state_path)
		free(state_path);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	hgd_cleanup_ssl(NULL);

	HGD_CLOSE_SYSLOG();

	exit (!exit_ok);
}
/* NOTE! -c is reserved for 'config file path' */
void
hgd_usage()
{
        printf("Usage: hgdc [opts] command [args]\n\n");
        printf("Commands include:\n");
        printf("    user-add <username> [password]	Add a user.\n");
        printf("    user-del <username>			Delete a user.\n");
        printf("    user-list				List users.\n");
        printf("    pause				Pause MPlayer.\n");
        printf("    skip				Next track.\n");
	/*
        printf("    user-disable username\tDisable a user account");
        printf("    user-chpw username\t\t\tChange a users password\n");
        printf("    user-enable username\t\t\Re-enable a user\n\n");
	*/
        printf("\n  Options include:\n");
	printf("    -c <path>		Location of config files\n");
        printf("    -d <path>		Location of state directory\n");
        printf("    -h			Show this message and exit\n");
        printf("    -x <level>		Set debug level (0-3)\n");
        printf("    -v			Show version and exit\n");
}

int
hgd_acmd_user_add(char **args)
{
	unsigned char		 salt[HGD_SHA_SALT_SZ];
	char			*salt_hex, *hash_hex;
	char			*user = args[0], *pass = args[1];
	int			 ret = HGD_OK;

	char			salt_ascii[HGD_SHA_SALT_SZ * 2 + 1];
	char			hash_ascii[HGD_SHA_SALT_SZ * 2 + 1];

	DPRINTF(HGD_D_INFO, "Adding user '%s'", user);

	memset(salt, 0, HGD_SHA_SALT_SZ);
	if (RAND_bytes(salt, HGD_SHA_SALT_SZ) != 1) {
		DPRINTF(HGD_D_ERROR, "can not generate salt");
		return (HGD_FAIL);
	}

	salt_hex = hgd_bytes_to_hex(salt, HGD_SHA_SALT_SZ);
	hgd_bytes_to_hex_buf(salt_hex, salt_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new user's salt '%s'", salt_ascii);

	hash_hex = hgd_sha1(pass, salt_hex);
	memset(pass, 0, strlen(pass));
	hgd_bytes_to_hex_buf(hash_hex, hash_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new_user's hash '%s'", hash_ascii);

	if (hgd_add_user(args[0], salt_hex, hash_hex) != HGD_OK)
		ret = HGD_FAIL;

	free(salt_hex);
	free(hash_hex);

	return (ret);
}

int
hgd_acmd_user_add_prompt(char **args)
{
	char			 pass[HGD_MAX_PASS_SZ];
	char			*new_args[2];

	if (hgd_readpassphrase_confirmed(pass) != HGD_OK)
		return (HGD_FAIL);

	new_args[0] = args[0];
	new_args[1] = pass;

	return (hgd_acmd_user_add(new_args));
}

int
hgd_acmd_user_del(char **args)
{
	if (hgd_delete_user(args[0]) != HGD_OK)
		return (HGD_FAIL);

	return (HGD_OK);
}

int
hgd_acmd_user_list(char **args)
{
	struct hgd_user_list	*list = hgd_get_all_users();
	int			 i;

	/* sssh */
	args = args;

	for (i = 0; i < list->n_users; i++)
		printf("%s\n", list->users[i]->name);

	hgd_free_user_list(list);
	free(list);

	return (HGD_OK);

}

int
hgd_acmd_pause(char **args)
{
	(void) args;

	return (hgd_mplayer_pipe_send("pause\n"));
}

int
hgd_acmd_skip(char **args)
{
	(void) args;

	return (hgd_mplayer_pipe_send("stop\n"));
}



struct hgd_admin_cmd admin_cmds[] = {
	{ "user-add", 2, hgd_acmd_user_add },
	{ "user-add", 1, hgd_acmd_user_add_prompt },
	{ "user-del", 1, hgd_acmd_user_del },
	{ "user-list", 0, hgd_acmd_user_list },
	{ "pause", 0, hgd_acmd_pause },
	{ "skip", 0, hgd_acmd_skip },
#if 0
	{ "user-disable", 1, hgd_acmd_user_disable },
	{ "user-chpw", 1, hgd_acmd_user_chpw },
	{ "user-enable", 1, hgd_acmd_user_enable },
#endif
	{ 0, 0, NULL }
};

int
hgd_parse_command(int argc, char **argv)
{
	struct hgd_admin_cmd	*acmd, *correct_acmd = NULL;

	DPRINTF(HGD_D_DEBUG, "Looking for command handler for '%s'", argv[0]);

	for (acmd = admin_cmds; acmd->cmd != 0; acmd++) {
		if ((acmd->num_args == argc -1) &&
		    (strcmp(acmd->cmd, argv[0]) == 0))
			correct_acmd = acmd;
	}

	if (correct_acmd == NULL) {
		DPRINTF(HGD_D_WARN, "Incorrect usage: '%s' with %d args",
		    argv[0], argc - 1);
		return (HGD_FAIL);
	}

	if (correct_acmd->handler(++argv) != HGD_OK)
		return (HGD_FAIL);

	return (HGD_OK);
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
	int			 dont_fork = dont_fork;
	long long int		 tmp_debuglevel;
	char			*tmp_state_path;
	struct stat		 st;

	cf = &cfg;
	config_init(cf);

	while (*config_locations != NULL) {
		/* Try and open usr config */
		DPRINTF(HGD_D_INFO, "Trying to read config from: %s",
		    *config_locations);

		/*
		 * XXX: can be removed when deb get new libconfig
		 * see hgd-playd.c
		 */
		if (stat(*config_locations, &st) < 0) {
			DPRINTF(HGD_D_INFO, "Could not stat %s",
			    *config_locations);
			config_locations--;
			continue;
		}

		if (config_read_file(cf, *config_locations)) {
			break;
		}

		DPRINTF(HGD_D_ERROR, "%s (line: %d)\n",
				config_error_text(cf),
				config_error_line(cf));

		config_locations--;
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

	/* -x */
	if (config_lookup_int64(cf, "debug", &tmp_debuglevel)) {
		hgd_debug = tmp_debuglevel;
		DPRINTF(HGD_D_DEBUG, "Set debug level to %d", hgd_debug);
	}

	config_destroy(cf);
#endif
	return (HGD_OK);
}


int
main(int argc, char **argv)
{
	char			 ch, *xdg_config_home;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	/* syslog as early as possible */
	HGD_INIT_SYSLOG();

	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s", HGD_GLOBAL_CFG_DIR HGD_SERV_CFG);

	xdg_config_home =  getenv("XDG_CONFIG_HOME");
	if (xdg_config_home == NULL) {
		xasprintf(&config_path[2], "%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR HGD_SERV_CFG );
	} else {
		xasprintf(&config_path[2], "%s%s",
		    xdg_config_home , "/hgd" HGD_SERV_CFG);

	}

	hgd_register_sig_handlers();
	state_path = xstrdup(HGD_DFL_DIR);
	hgd_init_mplayer_globals();

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "c:d:hvx:" "c:x:")) != -1) {
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
			break; /* next getopt will catch errors */
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

	DPRINTF(HGD_D_DEBUG, "Parsing options:2");
	while ((ch = getopt(argc, argv, "c:d:hvx:" "c:x:")) != -1) {
		switch (ch) {
		case 'c':
			break; /* already handled */
		case 'd':
			free(state_path);
			state_path = xstrdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set hgd dir to '%s'", state_path);
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

	if (hgd_parse_command(argc, argv) == -1)
		hgd_usage();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
