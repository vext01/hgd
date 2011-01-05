#ifndef __HGD_H
#define __HGD_H

#define HGD_DFL_DB_PATH			"/home/edd/hgd.db"
#define HGD_DFL_MPLAYER_PID_PATH	"/home/edd/hgd_mplayer.pid"
#define HGD_DFL_FILESTORE_PATH		"/home/edd/hgd_store"

#include <stdint.h>
#include <sqlite3.h>

extern uint8_t			 hgd_debug;

struct hgd_playlist_item {
	int			 id;
	char			*filename;
	char			*user;
	uint8_t			 playing;
	uint8_t			 finished;
};

struct hgd_session {
	int			sock_fd;
	struct sockaddr_in	*cli_addr;
	char			*cli_str;
	char			*user;
};

struct hgd_cmd_despatch {
	char			*cmd;
	uint8_t			n_args;
	int			(*handler)(struct hgd_session *, char **);
};

/* simple debug facility */
#define DPRINTF(x...)           do { if (hgd_debug)		\
					    fprintf(stderr, x); } while (0)
void				hgd_free_playlist_item(
				    struct hgd_playlist_item *);

/* wrappers */
void				*xmalloc(size_t);
int				 xasprintf(char **buf, char *fmt, ...);

/* socket ops */
void				 hgd_sock_send(int fd, char *msg);
void				 hgd_sock_send_line(int fd, char *msg);
char				*hgd_sock_recv_bin(int fd, ssize_t len);
char				*hgd_sock_recv_line(int fd);

/* misc */
sqlite3				*hgd_open_db(char *);

#endif
