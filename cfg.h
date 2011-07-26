#include <libconfig.h>
#include <stdint.h>

int	hgd_load_config(config_t *cf, char **config_locations);
void	hgd_cfg_daemonise(config_t *cf, char *service, int *background); 
void	hgd_cfg_netd_rdns(config_t *cf, uint8_t *lookup_client_dns);
void	hgd_cfg_statepath(config_t *cf, char **state_path);
void	hgd_cfg_netd_crypto(config_t *cf, uint8_t *crypro_pref);
void	hgd_cfg_fork(config_t *cf, char *service, uint8_t *single_client);
void	hgd_cfg_netd_flood_limit(config_t *cf, int *flood_limit);
void	hgd_cf_netd_ssl_privkey(config_t *cf, char **ssl_key_path);
void	hgd_cfg_netd_votesound(config_t *cf, int *req_votes);
void	hgd_cfg_netd_port(config_t *cf, int *port);
void	hgd_cfg_netd_max_filesize(config_t *cf, long int *max_upload_size);
void	hgd_cfg_netd_sslcert(config_t *cf, char **ssl_cert_path);
void	hgd_cfg_debug(config_t *cf, char* service, int8_t *hgd_debug);
void	hgd_cfg_netd_voteoff_sound(config_t *cf, char **vote_sound);


