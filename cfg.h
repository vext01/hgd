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

#ifndef HGD_CFG_H
#define HGD_CFG_H 1

#include <libconfig.h>
#include <stdint.h>

int	hgd_load_config(config_t *cf, char **config_locations);
void	hgd_cfg_daemonise(config_t *cf, char *service, int *background); 
void	hgd_cfg_netd_rdns(config_t *cf, uint8_t *lookup_client_dns);
void	hgd_cfg_statepath(config_t *cf, char **state_path);
void	hgd_cfg_crypto(config_t *cf, char* service, uint8_t *crypro_pref);
void	hgd_cfg_fork(config_t *cf, char *service, uint8_t *single_client);
void	hgd_cfg_netd_flood_limit(config_t *cf, int *flood_limit);
void	hgd_cf_netd_ssl_privkey(config_t *cf, char **ssl_key_path);
void	hgd_cfg_netd_votesound(config_t *cf, int *req_votes);
void	hgd_cfg_netd_port(config_t *cf, int *port);
void	hgd_cfg_netd_max_filesize(config_t *cf, long int *max_upload_size);
void	hgd_cfg_netd_sslcert(config_t *cf, char **ssl_cert_path);
void	hgd_cfg_debug(config_t *cf, char* service, int8_t *hgd_debug);
void	hgd_cfg_netd_voteoff_sound(config_t *cf, char **vote_sound);
void	hgd_cfg_playd_purgefs(config_t *cf, uint8_t *purge_finished_fs);
void	hgd_cfg_pluginpath(config_t *cf, char **hgd_py_plugin_dir);
void	hgd_cfg_playd_purgedb(config_t *cf, uint8_t *purge_finished_db);
void	hgd_cfg_c_colours(config_t *cf, uint8_t *colours_on);
void	hgd_cfg_c_maxitems(config_t *cf, uint8_t *hud_max_items);
void	hgd_cfg_c_hostname(config_t *cf, char **host);
void	hgd_cfg_c_port(config_t *cf, int *port);
void	hgd_cfg_c_password(config_t *cf, char **password, char *config_location);
void	hgd_cfg_c_refreshrate(config_t *cf, uint8_t *hud_refresh_speed);
void	hgd_cfg_c_username(config_t *cf, char** user);
void	hgd_cfg_c_debug(config_t *cf, int8_t *hgd_debug);

#endif
