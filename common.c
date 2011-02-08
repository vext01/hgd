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

#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hgd.h"

int8_t				 hgd_debug = 1; /* default to warn */
uint8_t				 dying = 0;
uint8_t				 exit_ok = 0;
pid_t				 pid = 0;

char				*debug_names[] = {
				    "error", "warn", "info", "debug"};

/* these are unused in client */
char				*hgd_dir = NULL;
char				*filestore_path = NULL;

/*
 * frees members of a playlist item, but not the item
 * itself, therefore allowing stack allocation if wished
 */
void
hgd_free_playlist_item(struct hgd_playlist_item *i)
{
	if (i->filename != NULL)
		free(i->filename);
	if (i->user != NULL)
		free(i->user);
}

/*
 * free a playlist's members but not the list itself
 */
void
hgd_free_playlist(struct hgd_playlist *list)
{
	unsigned int		i;

	for (i = 0; i < list->n_items; i ++) {
		hgd_free_playlist_item(list->items[i]);
		free(list->items[i]);
	}

	free(list->items);
}

void *
xmalloc(size_t sz)
{
	void			*ptr;

	ptr = malloc(sz);
	if (!ptr) {
		DPRINTF(HGD_D_ERROR, "Could not allocate");
		hgd_exit_nicely();
	}

	return ptr;
}

void *
xrealloc(void *old_p, size_t sz)
{
	void			*ptr;

	ptr = realloc(old_p, sz);
	if (!ptr) {
		DPRINTF(HGD_D_ERROR,"Could not reallocate");
		hgd_exit_nicely();
	}

	return ptr;
}

int
xasprintf(char **buf, char *fmt, ...)
{
	va_list			ap;
	int			ret;

	va_start(ap, fmt);
	ret = vasprintf(buf, fmt, ap);

	if (ret == -1) {
		DPRINTF(HGD_D_ERROR, "Can't allocate");
		hgd_exit_nicely();
	}

	return ret;
}

/* send binary over the socket */
void
hgd_sock_send_bin(int fd, char *msg, ssize_t sz)
{
	ssize_t		tot_sent = 0, sent;
	char		*next = msg;

	while (tot_sent != sz) {
		sent = send(fd, next, sz - tot_sent, 0);

		if (sent < 0) {
			DPRINTF(HGD_D_WARN, "Send failed");
			sent = 0;
			continue;
		} else
			DPRINTF(HGD_D_DEBUG, "Sent %d bytes", (int) sent);

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
			DPRINTF(HGD_D_WARN, "send: %s", SERROR);
			sent = 0;
		}
		sent_tot += sent;
	}

	DPRINTF(HGD_D_DEBUG, "Sent %d bytes", (int) len);
}

/* send a \r\n terminated line */
void
hgd_sock_send_line(int fd, char *msg)
{
	char			*term;

	xasprintf(&term, "%s\r\n", msg);
	hgd_sock_send(fd, term);
	free(term);

	DPRINTF(HGD_D_DEBUG, "Sent line: %s", msg);
}

/* recieve a specific size, free when done */
char *
hgd_sock_recv_bin(int fd, ssize_t len)
{
	ssize_t			recvd_tot = 0, recvd;
	char			*msg, *full_msg = NULL;
	struct pollfd		pfd;
	int			data_ready = 0, tries_left = 3;

	/* spin until something is ready */
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!dying && !data_ready) {
		data_ready = poll(&pfd, 1, INFTIM);
		if (data_ready == -1) {
			if (errno != EINTR) {
				DPRINTF(HGD_D_WARN, "poll error: %s", SERROR);
				dying = 1;
			}
			data_ready = 0;
		}
	}

	if (dying)
		hgd_exit_nicely();

	full_msg = xmalloc(len);
	msg = full_msg;

	while (recvd_tot != len && tries_left > 0) {
		recvd = recv(fd, msg, len - recvd_tot, 0);

		switch (recvd) {
		case 0:
			/* should not happen */
			DPRINTF(HGD_D_WARN, "No bytes recvd");
			tries_left--;
			continue;
		case -1:
			if (errno == EINTR)
				continue;
			DPRINTF(HGD_D_WARN, "recv: %s", SERROR);
			tries_left--;
		default:
			/* good */
			break;
		};

		msg += recvd;
		recvd_tot += recvd;
	}

	if (tries_left == 0) {
		DPRINTF(HGD_D_ERROR, "Gave up trying to recieve: %s", SERROR);
		return NULL;
	}

	return full_msg;
}

/*
 * recieve a line, free when done.
 * returns NULL on error.
 */
char *
hgd_sock_recv_line(int fd)
{
	ssize_t			recvd_tot = 0, recvd;
	char			recv_char, *full_msg = NULL;
	struct pollfd		pfd;
	int			data_ready = 0;

	/* spin until something is ready */
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!dying && !data_ready) {
		data_ready = poll(&pfd, 1, INFTIM);
		if (data_ready == -1) {
			if (errno != EINTR) {
				DPRINTF(HGD_D_WARN, "Poll error: %s", SERROR);
				dying = 1;
			}
			data_ready = 0;
		}
	}

	if (dying)
		hgd_exit_nicely();

	full_msg = xmalloc(HGD_MAX_LINE);

	do {
		/* recieve one byte */
		recvd = recv(fd, &recv_char, 1, 0);

		switch (recvd) {
		case 0:
			/* should not happen */
			DPRINTF(HGD_D_WARN, "No bytes recvd");
			return (NULL);
		case -1:
			if (errno == EINTR)
				continue;
			DPRINTF(HGD_D_WARN, "recv: %s", SERROR);
			return (NULL);
		default:
			/* good */
			break;
		};

		if (recvd_tot >= HGD_MAX_LINE)
			DPRINTF(HGD_D_ERROR, "Socket line was long");

		full_msg[recvd_tot] = recv_char;

		recvd_tot += recvd;
	} while ((recvd_tot >= 1) &&
	    (recvd_tot <= HGD_MAX_LINE) && (recv_char != '\n'));

	/* get rid of \r\n */
	if (full_msg[recvd_tot - 2] == '\r')
		full_msg[recvd_tot - 2] = 0;

	full_msg[recvd_tot - 1] = 0;
	full_msg[recvd_tot] = 0;
	return full_msg;
}

void
hgd_kill_sighandler(int sig)
{
	sig = sig; /* quiet */
	dying = 1;
}

void
hgd_register_sig_handlers()
{
	signal(SIGTERM, hgd_kill_sighandler);
	signal(SIGABRT, hgd_kill_sighandler);
	signal(SIGINT, hgd_kill_sighandler);
}

uint8_t
hgd_is_ip_addr(char *str)
{
	struct sockaddr_in	sa;
	int			res;

	res = inet_pton(AF_INET, str, &(sa.sin_addr));
	return res != 0;
}

/* make state dir if not existing */
void
hgd_mk_state_dir()
{
	if (mkdir(hgd_dir, 0700) != 0) {
		if (errno != EEXIST) {
			DPRINTF(HGD_D_ERROR, "%s: %s", hgd_dir, SERROR);
			hgd_exit_nicely();
		}
	}

	/* make filestore if not existing */
	if (mkdir(filestore_path, 0700) != 0) {
		if (errno != EEXIST) {
			DPRINTF(HGD_D_ERROR, "%s:%s", filestore_path, SERROR);
			hgd_exit_nicely();
		}
	}
}

void
hgd_print_version()
{
	printf("Hackathon Gunther Daemon v" HGD_VERSION "\n");
	printf("(C) Edd Barrett 2011\n");
}
