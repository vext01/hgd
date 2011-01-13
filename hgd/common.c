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

struct hgd_playlist_item *
hgd_new_playlist_item()
{
	struct hgd_playlist_item	*item;

	item = xmalloc(sizeof(struct hgd_playlist_item));
	memset(item, 0, sizeof(struct hgd_playlist_item));

	return (item);
}

void hgd_free_playlist_item(struct hgd_playlist_item *i)
{
	if (i->filename != NULL) {
		DPRINTF("[%s]\n", i->filename);
		free(i->filename);
	}
	if (i->user != NULL)
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

void *
xrealloc(void *old_p, size_t sz)
{
	void			*ptr;

	ptr = realloc(old_p, sz);
	if (!ptr)
		fprintf(stderr, "%s: could not reallocate\n", __func__);

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

/* XXX code review these functions, they are dirty */

/* send binary over the socket */
void
hgd_sock_send_bin(int fd, char *msg, ssize_t sz)
{
	ssize_t		tot_sent = 0, sent;
	char		*next = msg;

	while (tot_sent != sz) {
		sent = send(fd, next, sz - tot_sent, 0);

		if (sent < 0) {
			fprintf(stderr, "%s: send failed\n", __func__);
			sent = 0;
			continue;
		} else
			DPRINTF("%s: sent %d bytes\n", __func__, (int) sent);

		msg += sent;
		tot_sent += sent;
	}
}

/* send a message onto the network */
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

	DPRINTF("%s: sent %d bytes\n", __func__, (int) len);
}

/* send a \r\n terminated line */
void
hgd_sock_send_line(int fd, char *msg)
{
	char			*term;

	xasprintf(&term, "%s\r\n", msg);
	hgd_sock_send(fd, term);
	free(term);

	DPRINTF("%s: sent line: %s\n", __func__, msg);
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
			warn("%s: recv", __func__);
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


