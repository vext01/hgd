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

#ifdef HAVE_LIBCONFIG /* entire file */

#include <limits.h>

#include "cfg.h"
#include "hgd.h"
#include "net.h"

int
hgd_load_config(config_t *cf, char **config_locations)
{
	struct stat		 st;

	config_init(cf);

	while (*config_locations != NULL) {

		/* Try and open usr config */
		DPRINTF(HGD_D_INFO, "Trying to read config from - %s",
		    *config_locations);

		if ( stat (*config_locations, &st) < 0 ) {
			DPRINTF(HGD_D_INFO, "Could not stat %s",
			    *config_locations);
			config_locations--;
			continue;
		}

		if (config_read_file(cf, *config_locations)) {
			break;
		} else {
			DPRINTF(HGD_D_ERROR, "%s (line: %d)",
			    config_error_text(cf),
			    config_error_line(cf));

			config_locations--;
		}
	}

	if (*config_locations == NULL) {
		config_destroy(cf);
		return (HGD_FAIL);
	} else {
		return (HGD_OK);
	}
}

void
hgd_cfg_daemonise(config_t *cf, char* service, int* background)
{
	/* -B */
	int			 tmp_background;
	char			*lookup;

	xasprintf(&lookup, "%s:daemonise", service);

	if (config_lookup_bool(cf, service, &tmp_background)) {
		*background = tmp_background;
		DPRINTF(HGD_D_DEBUG, "%s to background daemon",
		    *background ? "Going" : "Not going");
	}

	free(lookup);

}

void
hgd_cfg_netd_rdns(config_t *cf, uint8_t *lookup_client_dns)
{
	int			tmp_no_rdns;

	/* -D */
	if (config_lookup_bool(cf, "netd.rdns_lookup", &tmp_no_rdns)) {
		*lookup_client_dns = tmp_no_rdns;
		DPRINTF(HGD_D_DEBUG, "%s reverse dns lookups",
		    *lookup_client_dns ? "Doing" : "Not doing");
	}
}

void
hgd_cfg_statepath(config_t *cf, char **state_path)
{
	char			*tmp_state_path;
	/* -d */
	if (config_lookup_string(cf,
	    "state_path", (const char **) &tmp_state_path)) {
		if (*state_path != NULL) free(*state_path);
		*state_path = strdup(tmp_state_path);
		DPRINTF(HGD_D_DEBUG,
		    "Set hgd state path to '%s'", *state_path);
	}
}

void
hgd_cfg_crypto(config_t *cf, char *service, uint8_t *crypto_pref)
{
	char			*crypto;
	/* -e -E */
	if (config_lookup_string(cf, "crypto", (const char **) &crypto)) {
		if (strcmp(crypto, "always") == 0) {
			DPRINTF(HGD_D_DEBUG, "%s will insist upon cryto",
			    service);
			*crypto_pref = HGD_CRYPTO_PREF_ALWAYS;
		} else if (strcmp(crypto, "never") == 0) {
			DPRINTF(HGD_D_DEBUG, "%s will insist upon "
			   " no crypto", service);
			*crypto_pref = HGD_CRYPTO_PREF_NEVER;
		} else if (strcmp(crypto, "if_avaliable") == 0) {
			DPRINTF(HGD_D_DEBUG,
			    "%s will use crypto if avaliable",
			    service);
		} else {
			DPRINTF(HGD_D_WARN,
			    "Invalid crypto option, using default");
		}

	}
}

void
hgd_cfg_fork(config_t *cf, char *service, uint8_t *single_client)
{
	/* -f */
	int			tmp_dont_fork;
	char			*lookup;

	xasprintf(&lookup, "%s:dont_fork", service);

	if (config_lookup_bool(cf, lookup, &tmp_dont_fork)) {
		*single_client = tmp_dont_fork;
		DPRINTF(HGD_D_DEBUG,
		    "Chose to %sfork", *single_client ? "not " : "");
	}

	free (lookup);
}

void
hgd_cfg_netd_flood_limit(config_t *cf, int *flood_limit)
{
	/* -F */
	long long int		tmp_flood_limit;

	if (config_lookup_int64(cf, "netd.flood_limit", &tmp_flood_limit)) {
		*flood_limit = tmp_flood_limit;
		DPRINTF(HGD_D_DEBUG, "Flood limit set to %d",
		    *flood_limit);
	}
}

void
hgd_cf_netd_ssl_privkey(config_t *cf, char **ssl_key_path)
{
	/* -k */
	char			*tmp_ssl_key_path;

	if (config_lookup_string(cf,
	    "netd.ssl.privatekey", (const char**)&tmp_ssl_key_path)) {
		if (*ssl_key_path != NULL) free(*ssl_key_path);
		*ssl_key_path = xstrdup(tmp_ssl_key_path);
		DPRINTF(HGD_D_DEBUG,
		    "Set ssl private key path to '%s'", *ssl_key_path);
	}
}

void
hgd_cfg_netd_votesound(config_t *cf, int *req_votes)
{
	/* -n */
	long long int		tmp_req_votes;

	if (config_lookup_int64(cf, "netd.voteoff_count", &tmp_req_votes)) {
		*req_votes = tmp_req_votes;
		DPRINTF(HGD_D_DEBUG, "Set required-votes to %d", *req_votes);
	}
}

void
hgd_cfg_netd_port(config_t *cf, int *port)
{
	/* -p */
	long long int		tmp_port;

	if (config_lookup_int64(cf, "netd.port", &tmp_port)) {
		*port = tmp_port;
		DPRINTF(HGD_D_DEBUG, "Set port to %d", *port);
	}
}

void
hgd_cfg_netd_max_filesize(config_t *cf, long long int *max_upload_size)
{
	/* -s */
	if (config_lookup_int64(cf,
	    "netd.max_file_size", max_upload_size)) {
		*max_upload_size = (*max_upload_size) * HGD_MB;
		DPRINTF(HGD_D_DEBUG, "Set max upload size to %lld",
		    *max_upload_size);
	}
}

void
hgd_cfg_netd_sslcert(config_t *cf, char **ssl_cert_path)
{
	char			*tmp_ssl_cert_path;
	/* -S */
	if (config_lookup_string(cf,
	    "netd.ssl.cert", (const char **) &tmp_ssl_cert_path)) {
		if (*ssl_cert_path != NULL) free(*ssl_cert_path);
		*ssl_cert_path = xstrdup(tmp_ssl_cert_path);
		DPRINTF(HGD_D_DEBUG, "Set cert path to '%s'", *ssl_cert_path);
	}
}

void
hgd_cfg_debug(config_t *cf, char* service, int8_t *debug)
{
	/* -x */
	long long int		 tmp_hgd_debug;
	char			*lookup;

	xasprintf(&lookup, "%s:dont_fork", service);

	if (config_lookup_int64(cf, lookup, &tmp_hgd_debug)) {
		*debug = tmp_hgd_debug;
		DPRINTF(HGD_D_DEBUG, "Set debug level to %d", *debug);
	}

	free(lookup);
}

void
hgd_cfg_netd_voteoff_sound(config_t *cf, char **vote_sound)
{
	/* -y */
	char			*tmp_vote_sound;

	if (config_lookup_string(cf, "netd.voteoff_sound",
		    (const char **) &tmp_vote_sound)) {
		if (*vote_sound != NULL) free(*vote_sound);
		*vote_sound = xstrdup(tmp_vote_sound);
		DPRINTF(HGD_D_DEBUG, "Set voteoff sound to '%s'", *vote_sound);
	}
}

void
hgd_cfg_playd_purgefs(config_t *cf, uint8_t *purge_finished_fs)
{
	/* -p */
	int			tmp_purge_fin_fs;

	if (config_lookup_bool(cf, "playd.purge_fs", &tmp_purge_fin_fs)) {
		*purge_finished_fs = tmp_purge_fin_fs;
		DPRINTF(HGD_D_DEBUG,
		    "fs purging is %s", (*purge_finished_fs ? "on" : "off"));
	}
}

void
hgd_cfg_pluginpath(config_t *cf, char **hgd_py_plugin_dir)
{
	/* -P */
	char			*tmp_py_dir;

	if (config_lookup_string(cf, "py_plugins.plugin_path",
	    (const char **) &tmp_py_dir)) {
		if (*hgd_py_plugin_dir != NULL)
			free(*hgd_py_plugin_dir);

		*hgd_py_plugin_dir = strdup(tmp_py_dir);
		DPRINTF(HGD_D_DEBUG,"Setting Python plugin path to %s",
		    *hgd_py_plugin_dir);
	}
}

void
hgd_cfg_playd_purgedb(config_t *cf, uint8_t *purge_finished_db)
{
	/* -p */
	int			tmp_purge_fin_db;

	if (config_lookup_bool(cf, "playd.purge_db", &tmp_purge_fin_db)) {
		*purge_finished_db = tmp_purge_fin_db;
		DPRINTF(HGD_D_DEBUG,
		    "db purging is %s", (*purge_finished_db ? "on" : "off"));
	}
}

void
hgd_cfg_c_colours(config_t *cf, uint8_t *colours_on)
{
	/* -a -A */
	int			tmp_colours_on;

	if (config_lookup_bool(cf, "colours", &tmp_colours_on)) {
		*colours_on = tmp_colours_on;
		DPRINTF(HGD_D_DEBUG, "colours %s", *colours_on ? "on" : "off");
	}
}

void
hgd_cfg_c_maxitems(config_t *cf, uint8_t *hud_max_items)
{
	/* -m */
	long long int		tmp_hud_max_items;

	if (config_lookup_int64(cf, "max_items", &tmp_hud_max_items)) {
		*hud_max_items = tmp_hud_max_items;
		DPRINTF(HGD_D_DEBUG, "max items=%d", *hud_max_items);
	}
}

void
hgd_cfg_c_hostname(config_t *cf, char **host)
{
	/* -s */
	char			*tmp_host;

	if (config_lookup_string(cf, "hostname", (const char **) &tmp_host)) {
		if (*host != NULL) free(*host);
		*host = xstrdup(tmp_host);
		DPRINTF(HGD_D_DEBUG, "host=%s", *host);
	}
}

void
hgd_cfg_c_port(config_t *cf, int *port)
{
	/* -p */
	long long int			tmp_port;

	if (config_lookup_int64(cf, "port", &tmp_port)) {
		*port = tmp_port;
		DPRINTF(HGD_D_DEBUG, "port=%d", *port);
	}
}

void
hgd_cfg_c_password(config_t *cf, char **password, char *config_location)
{
	/* password */
	char			*tmp_password;
	struct stat		 st;

	if ( stat (config_location, &st) < 0 ) {
		DPRINTF(HGD_D_INFO, "Could not stat %s, skipping looking "
		    "up password.", config_location);
		return;
	}

	if (config_lookup_string(cf, "password",
	    (const char**) &tmp_password)) {
		if (st.st_mode & (S_IRWXG | S_IRWXO)) {
			DPRINTF(HGD_D_ERROR,
				"Config file with your password in is "
				"readable by other people. Please chmod it.\n"
				"# chmod 500 %s", config_location);
			hgd_exit_nicely();
		}

		*password = xstrdup(tmp_password);
		DPRINTF(HGD_D_DEBUG, "Set password from config");
	}
}

void
hgd_cfg_c_refreshrate(config_t *cf, uint8_t *hud_refresh_speed)
{
	/* -r */
	long long int		tmp_hud_refresh_rate;

	if (config_lookup_int64(cf, "refresh_rate", &tmp_hud_refresh_rate)) {
		*hud_refresh_speed = tmp_hud_refresh_rate;
		DPRINTF(HGD_D_DEBUG, "refresh rate=%d", *hud_refresh_speed);
	}
}

void
hgd_cfg_c_username(config_t *cf, char** user)
{
	/* -u */
	char			*tmp_user;

	if (config_lookup_string(cf, "username", (const char**) &tmp_user)) {
		if (*user != NULL) free(*user);
		*user = strdup(tmp_user);
		DPRINTF(HGD_D_DEBUG, "user='%s'", *user);
	}
}

void
hgd_cfg_c_debug(config_t *cf, int8_t *debug)
{
	/* -x */
	long long int		tmp_dbglevel;

	if (config_lookup_int64(cf, "debug", &tmp_dbglevel)) {
		*debug = tmp_dbglevel;
		DPRINTF(HGD_D_DEBUG, "debug level=%d", *debug);
	}
}

char*
hgd_get_XDG_userprefs_location(enum SERVICE service)
{
	char *xdg_config_home =  getenv(HGD_USR_CFG_ENV);
	char *config_path;
	char *serv_str = NULL;

	switch (service) {
	case netd:
	case playd:
		serv_str = HGD_SERV_CFG;
		break;
	case hgdc:
		serv_str = HGD_CLI_CFG;
		break;
	default:
		/*progammer error*/
		printf("Invalid option in hgd_get_XDG_userprefs_location");
		exit(-1);
	}

	if (xdg_config_home == NULL) {
		xasprintf(&config_path, "%s%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR, serv_str );
	} else {
		xasprintf(&config_path, "%s%s%s",
		    xdg_config_home , "/hgd", serv_str);
	}

	return config_path;

}
#if 0 /* lets not forget the lessons of our past */

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

#endif

#endif /* HAVE_LIBCONFIG */
