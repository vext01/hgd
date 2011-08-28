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

#ifndef __HGD_H
#define __HGD_H

#ifndef INFTIM
#define INFTIM -1
#endif

#define HGD_VERSION		PACKAGE_VERSION
#define HGD_PROTO_VERSION_MAJOR	4
#define HGD_PROTO_VERSION_MINOR 1

/* misc */
#define HGD_DFL_REQ_VOTES	3
#define HGD_PID_STR_SZ		10
#define HGD_ID_STR_SZ		40 /* 8byte int */
#define HGD_SHA_SALT_SZ		20
#define HGD_MAX_PASS_SZ		20
#define HGD_MAX_USER_QUEUE	5
#define HGD_MB			(1024L * 1024L)
#define HGD_UNIQ_FILE_PFX	"XXXXXXXX-"

/* paths */
#define HGD_DFL_DIR		"/var/hgd"
#define HGD_DB_NAME		"hgd.db"
#define HGD_FILESTORE_NAME	"files"
#define HGD_DFL_SVR_CONF_DIR	"/etc/hgd"

/* networking */
#define HGD_DFL_PORT		6633
#define HGD_DFL_HOST		"127.0.0.1"
#define HGD_DFL_BACKLOG		10
#define HGD_DFL_MAX_UPLOAD	(HGD_MB * 100L)
#define HGD_MAX_LINE		256
#define HGD_MAX_BAD_COMMANDS	3
#define HGD_BINARY_CHUNK	4096
#define HGD_BINARY_RECV_SZ	16384
#define	HGD_MAX_PROTO_TOKS	3
#define HGD_GREET		"ok|HGD-" HGD_VERSION
#define HGD_BYE			"ok|Catch you later d00d!"

/* SSL */
#define HGD_DFL_CERT_FILE	HGD_DFL_SVR_CONF_DIR "/certificate.crt"
#define HGD_DFL_KEY_FILE	HGD_DFL_SVR_CONF_DIR "/privkey.key"

#define	HGD_CRYPTO_PREF_ALWAYS	0
#define HGD_CRYPTO_PREF_IF_POSS	1
#define HGD_CRYPTO_PREF_NEVER	2

/* Config files */
#define HGD_GLOBAL_CFG_DIR	HGD_DFL_SVR_CONF_DIR
#define HGD_USR_CFG_ENV		"XDG_CONFIG_HOME"
#define HGD_USR_CFG_DIR		"/.config/hgd"

#define HGD_CLI_CFG		"/hgdc.rc"
#define HGD_SERV_CFG		"/hgd.rc"

/* Function return values */
#define HGD_FAIL		(-1)
#define HGD_OK			(0)

/* ANSII colours */
#define ANSII_YELLOW		(colours_on ? "\033[33m" : "")
#define ANSII_RED		(colours_on ? "\033[31m" : "")
#define ANSII_GREEN		(colours_on ? "\033[32m" : "")
#define ANSII_WHITE		(colours_on ? "\033[0m" : "")

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

extern int8_t			  hgd_debug;
extern uint8_t			  dying;
extern uint8_t			  restarting;
extern char			**cmd_line_args;
extern uint8_t			  exit_ok;
extern char			 *debug_names[];
extern int			  syslog_error_map[];
extern pid_t			  pid;
extern const char		 *hgd_component;

extern char			 *state_path;
extern char			 *filestore_path;

struct hgd_user {
	char			*name;
	int			 perms;
};

struct hgd_user_list {
	struct hgd_user		**users;
	int			 n_users;
};

struct hgd_playlist_item {
	int			 id;
	char			*filename;
	char			*tag_artist;
	char			*tag_title;
	char			*user;
	uint8_t			 playing;
	uint8_t			 finished;
};

struct hgd_playlist {
	unsigned int			n_items;
	struct hgd_playlist_item	**items;
};

/* server side client info */
struct hgd_session {
	int			sock_fd;
	struct sockaddr_in	*cli_addr;
	char			*cli_str;
	struct hgd_user		*user;
	SSL			*ssl;
};

struct hgd_admin_cmd {
	char			*cmd;
	int			num_args;
	int			(*handler)(char **args);
};

/* server command despatch */
struct hgd_cmd_despatch {
	char			*cmd;
	uint8_t			 n_args;
	/*
	 * read carefully:
	 * 'secure' means that when the server is ONLY accepting SSL
	 * connections, the client must have sent an 'encrypt' command
	 * which has completed successfully before this command can
	 * be used.
	 */
	uint8_t			 secure;
	int			(*handler)(struct hgd_session *, char **);
};

/* client request despatch */
struct hgd_req_despatch {
	char			*req;
	uint8_t			 n_args;
	uint8_t			 need_auth;
	int			 (*handler)(int n_args, char **);
	uint8_t			 varargs; /* if !0, n_args is the minimum */
};

/* debug levels */
#define HGD_D_ERROR		0
#define HGD_D_WARN		1
#define HGD_D_INFO		2
#define HGD_D_DEBUG		3

/* simple debug facility */
#define DPRINTF(level, x...)						\
	do {								\
		if (level <= hgd_debug) {				\
			fprintf(stderr, "[%s - %08d %s:%s():%d]\n\t",	\
			    debug_names[level], getpid(),		\
			    __FILE__, __func__, __LINE__);		\
			fprintf(stderr, x);				\
			fprintf(stderr, "\n");				\
			/* same again for syslog */			\
			syslog(syslog_error_map[level],			\
			    "[%s - %08d %s:%s():%d]\n\t",		\
			    debug_names[level], getpid(),		\
			    __FILE__, __func__, __LINE__);		\
			syslog(syslog_error_map[level], x);		\
			closelog();					\
		}							\
	} while (0)

#define HGD_INIT_SYSLOG_DAEMON()	openlog(hgd_component, 0, LOG_DAEMON);
#define HGD_INIT_SYSLOG()		openlog(hgd_component, 0, 0);
#define HGD_CLOSE_SYSLOG()		closelog();

#if defined(__linux__)
	#define RESET_GETOPT() do {optind = 1;} while (0)
#elif defined (__OpenBSD__) || defined(__FreeBSD__) || defined(__APPLE__)
	#define RESET_GETOPT() do {optind = 1;optreset = 1;} while (0)
#else
	#define RESET_GETOPT() do {optind = 1;} while (0
	#warning "RESET_GETOPT() has not been tested on your system"
#endif

/* generic error string */
#define SERROR			strerror(errno)

void				 hgd_free_playlist_item(
				    struct hgd_playlist_item *);
void				 hgd_free_playlist(struct hgd_playlist *);
void				 hgd_free_user(struct hgd_user *u);
void				 hgd_free_user_list(struct hgd_user_list *ul);

/* wrappers */
void				*xmalloc(size_t);
void				*xrealloc(void *, size_t);
int				 xasprintf(char **buf, char *fmt, ...);
void				*xcalloc(size_t sz, size_t size);
char				*xstrdup(const char *s);

/* socket ops */
void				 hgd_cleanup_ssl(SSL_CTX **ctx);
void				 hgd_sock_send(int fd, char *msg);
void				 hgd_sock_send_line(int fd, SSL* ssl,
				     char *msg);
char				*hgd_sock_recv_bin(int fd, SSL* ssl,
				     ssize_t len);
char				*hgd_sock_recv_line(int fd, SSL* ssl);
void				 hgd_sock_send_bin(int fd, SSL* ssl,
				     char *, ssize_t);
int				 hgd_setup_ssl_ctx(SSL_METHOD **method,
				     SSL_CTX **ctx, int server,
				     char *, char *);

/* misc */
uint8_t				 hgd_is_ip_addr(char *str);
void				 hgd_mk_state_dir(void);
void				 hgd_print_version(void);
void				 hgd_exit_nicely(void);
void				 hgd_kill_sighandler(int sig);
void				 hgd_register_sig_handlers(void);
char				*hgd_sha1(const char *msg, const char *salt);
char				*hgd_bytes_to_hex(unsigned char *bs, int len);
void				 hgd_bytes_to_hex_buf(char*, char*, int len);
int				 hgd_readpassphrase_confirmed(
				     char buf[HGD_MAX_PASS_SZ]);
int				 hgd_daemonise(void);
void				 hgd_restart_myself(void);
int				 hgd_cache_exec_context(char **args);

#endif
