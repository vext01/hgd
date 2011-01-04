#ifndef __HGD_H
#define __HGD_H

#define HGD_DFL_DB_PATH		"/home/edd/hgd.db"
#define HGD_DFL_MPLAYER_PID_PATH "/home/edd/hgd_mplayer.pid"

#include <stdint.h>

struct hgd_playlist_item {
	int			id;
	char			*filename;
	char			*user;
	uint8_t			playing;
	uint8_t			finished;
};

/* simple debug facility */
#define DPRINTF(x...)           do { if (hgd_debug)		\
					    fprintf(stderr, x); } while (0)
void				hgd_free_playlist_item(
				    struct hgd_playlist_item *);

void				*xmalloc(size_t);
int				xasprintf(char **buf, char *fmt, ...);

#endif
