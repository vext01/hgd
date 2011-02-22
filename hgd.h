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

#define HGD_VERSION		"0.2-current"

/* paths */
#define HGD_DFL_DIR		"/var/hgd"
#define HGD_DB_NAME		"hgd.db"
#define HGD_MPLAYER_PID_NAME	"mplayer.pid"
#define HGD_FILESTORE_NAME	"files"
#define HGD_DFL_SVR_CONF_DIR	"/etc/hgd"

/* networking */
#define HGD_DFL_PORT		6633
#define HGD_DFL_BACKLOG		10
#define HGD_DFL_MAX_UPLOAD	(1024 * 1024 * 100)
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

/* misc */
#define HGD_DFL_REQ_VOTES	3
#define HGD_PID_STR_SZ		10
#define HGD_SHA_SALT_SZ		20
#define HGD_MAX_PASS_SZ		20

/* Function return values */
#define HGD_FAIL		(-1)
#define HGD_OK			(0)

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

extern int8_t			 hgd_debug;
extern uint8_t			 dying;
extern uint8_t			 exit_ok;
extern char			*debug_names[];
extern pid_t			 pid;

extern char			*hgd_dir;
extern char			*filestore_path;

struct hgd_user {
	char			*name;
	int			 perms;
};

struct hgd_playlist_item {
	int			 id;
	char			*filename;
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
	int			 (*handler)(char **);
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
		}							\
	} while (0)

#define PRINT_SSL_ERR(msg)						\
	do {								\
		char error[255];					\
		unsigned long err;					\
		err = ERR_get_error();					\
		ERR_error_string_n(err, error, sizeof(error));		\
		DPRINTF(HGD_D_ERROR, "%s: %s", msg, error);		\
	} while(0)

/* generic error string */
#define SERROR			strerror(errno)

void				 hgd_free_playlist_item(
				    struct hgd_playlist_item *);
void				 hgd_free_playlist(struct hgd_playlist *);

/* wrappers */
void				*xmalloc(size_t);
void				*xrealloc(void *, size_t);
int				 xasprintf(char **buf, char *fmt, ...);
void				*xcalloc(size_t sz, size_t size);

/* socket ops */
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
void				 hgd_mk_state_dir();
void				 hgd_print_version();
void				 hgd_exit_nicely();
void				 hgd_kill_sighandler(int sig);
void				 hgd_register_sig_handlers();
char				*hgd_sha1(const char *msg, const char *salt);
char				*hgd_bytes_to_hex(unsigned char *bs, int len);

#endif
