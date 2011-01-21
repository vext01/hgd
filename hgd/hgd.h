/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
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

#define HGD_VERSION			"0.1"

/* paths */
#define HGD_DFL_DIR			"/var/hgd"
#define HGD_DB_NAME			"hgd.db"
#define HGD_MPLAYER_PID_NAME		"mplayer.pid"
#define HGD_FILESTORE_NAME		"files"

/* networking */
#define HGD_DFL_PORT			6633
#define HGD_DFL_BACKLOG			5

/* database schema */
#define HGD_DBS_FILENAME_LEN		"50"
#define HGD_DBS_USERNAME_LEN		"15"

/* misc */
#define HGD_DFL_REQ_VOTES		3

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include <sqlite3.h>

extern int8_t			 hgd_debug;
extern uint8_t			 dying;
extern uint8_t			 exit_ok;
extern char			*debug_names[];
extern pid_t			 pid;

struct hgd_playlist_item {
	int			 id;
	char			*filename;
	char			*user;
	uint8_t			 playing;
	uint8_t			 finished;
};

/* server side client info */
struct hgd_session {
	int			sock_fd;
	struct sockaddr_in	*cli_addr;
	char			*cli_str;
	char			*user;
};

/* server command despatch */
struct hgd_cmd_despatch {
	char			*cmd;
	uint8_t			n_args;
	int			(*handler)(struct hgd_session *, char **);
};

/* client request despatch */
struct hgd_req_despatch {
	char			*req;
	uint8_t			n_args;
	int			(*handler)(char **);
};

/* debug levels */
#define HGD_DEBUG_ERROR			0
#define HGD_DEBUG_WARN			1
#define HGD_DEBUG_INFO			2
#define HGD_DEBUG_DEBUG			3

/* simple debug facility */
#define DPRINTF(level, x...)						\
	do {								\
		if (level <= hgd_debug) {				\
			fprintf(stderr, "[%s - %08d %s:%d]\n\t",	\
			    debug_names[level], getpid(),		\
			    __FILE__, __LINE__);			\
			fprintf(stderr, x);				\
		}							\
	} while (0)
#define serror()			strerror(errno)


struct hgd_playlist_item	*hgd_new_playlist_item();
void				hgd_free_playlist_item(
				    struct hgd_playlist_item *);

/* wrappers */
void				*xmalloc(size_t);
void				*xrealloc(void *, size_t);
int				 xasprintf(char **buf, char *fmt, ...);

/* socket ops */
void				 hgd_sock_send(int fd, char *msg);
void				 hgd_sock_send_line(int fd, char *msg);
char				*hgd_sock_recv_bin(int fd, ssize_t len);
char				*hgd_sock_recv_line(int fd);
void				hgd_sock_send_bin(int, char *, ssize_t);

void				hgd_exit_nicely();
void				hgd_kill_sighandler(int sig);
void				hgd_register_sig_handlers();

/* misc */
sqlite3				*hgd_open_db(char *);

#endif
