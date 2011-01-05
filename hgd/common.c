#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sqlite3.h>

#include "hgd.h"

uint8_t				 hgd_debug = 1;

void hgd_free_playlist_item(struct hgd_playlist_item *i)
{
	free(i->filename);
	free(i->user);
	free(i);
}

void *
xmalloc(size_t sz)
{
	void			*ptr;

	ptr = malloc(sz);
	if (!ptr)
		fprintf(stderr, "%s: could not allocate\n", __func__);

	return ptr;
}

int
xasprintf(char **buf, char *fmt, ...)
{
	va_list			ap;
	int			ret;

	va_start(ap, fmt);
	ret = vasprintf(buf, fmt, ap);

	if (ret == -1)
		fprintf(stderr, "%s: can't allocate", __func__);

	return ret;
}

/* send a raw message onto the network */
void
hgd_sock_send(int fd, char *msg)
{
	ssize_t			sent_tot = 0, sent, len;

	len = strlen(msg);

	while (sent_tot != len) {
		sent = send(fd, msg, len - sent_tot, 0);
		if (sent < 0) {
			warn("%s: send\n", __func__);
			sent = 0;
		}
		sent_tot += sent;
	}
}

/* send a \r\n terminated line */
void
hgd_sock_send_line(int fd, char *msg)
{
	char			*term;

	xasprintf(&term, "%s\r\n", msg);
	hgd_sock_send(fd, term);
	free(term);
}

/* recieve a specific size, free when done */
/* XXX set a timeout */
char *
hgd_sock_recv_bin(int fd, ssize_t len)
{
	ssize_t			recvd_tot = 0, recvd;
	char			*msg, *full_msg = NULL;

	full_msg = xmalloc(len);
	msg = full_msg;

	while (recvd_tot != len) {
		recvd = recv(fd, msg, len - recvd_tot, 0);
		msg += recvd;
		recvd_tot += recvd;
	}
#if 0
		msg = xmalloc(len - recvd_tot);
		recvd = recv(fd, msg, len - recvd_tot, 0);

		if (recvd < 0) {
			warn("%s: recv\n", __func__);
			free(msg);
			continue;
		}

		if (full_msg != NULL) {
			/* reallocate */
			tmp = full_msg;
			xasprintf(&full_msg, "%s%s", full_msg, msg);
			free(tmp);
		} else /* first time round */
			full_msg = strdup(msg);

		recvd_tot += recvd;
		free(msg);
	}
#endif

	return full_msg;
}

/* recieve a line, free when done */
#define HGD_LINE_CHUNK		128
char *
hgd_sock_recv_line(int fd)
{
	ssize_t			recvd_tot = 0, recvd;
	char			*msg, *full_msg = NULL, *tmp;

	do {
		msg = xmalloc(HGD_LINE_CHUNK + 1); /* \0 */
		recvd = recv(fd, msg, HGD_LINE_CHUNK, 0);

		if (recvd < 0) {
			warn("%s: recv\n", __func__);
			free(msg);
			continue;
		}

		DPRINTF("%s: got %d bytes\n", __func__, (int) recvd);
		msg[recvd] = 0; /* terminate */

		if (full_msg != NULL) {
			/* reallocate */
			tmp = full_msg;
			xasprintf(&full_msg, "%s%s", full_msg, msg);
			free(tmp);
		} else /* first time round */
			full_msg = strdup(msg);

		recvd_tot += recvd;
		free(msg);
	} while ((recvd_tot >= 1) && (full_msg[recvd_tot -1] != '\n'));

	return full_msg;
}
