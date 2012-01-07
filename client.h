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

#define _GNU_SOURCE	/* linux */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <libgen.h>

#ifdef __linux__
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif

#include "config.h"
#include "hgd.h"
#include "net.h"
#include "user.h"
#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif

#define HGD_NUM_TRACK_FIELDS		14

struct hgd_resp_err {
	char		*code;
	char		*meaning;
};


extern struct hgd_resp_err hgd_resp_errs[];

extern char		*user, *host, *password;
extern int		 port, sock_fd;
extern uint8_t		 max_playlist_items;

extern SSL		*ssl;
extern SSL_METHOD	*method;
extern SSL_CTX		*ctx;
extern uint8_t		 crypto_pref, server_ssl_capable, authenticated;
extern uint8_t		 hud_refresh_speed, colours_on;

int			 hgd_client_edit_config();
int			 hgd_client_login(int fd, SSL *ssl, char *username);
int			 hgd_setup_socket();
int			 hgd_check_svr_response(char *resp, uint8_t x);
int			 hgd_negotiate_crypto();
int			 hgd_encrypt(int fd);
int			 hgd_print_pretty_server_response(char *resp_line);
int			 hgd_check_svr_proto();
int			 hgd_cli_get_playlist(struct hgd_playlist **list);
int			 hgd_cli_populate_track(
			     struct hgd_playlist_item **it, char *resp);
int			 hgd_cli_queue_track(char *filename, void *arg,
    			     int(*cb)(void *arg, float progress));
