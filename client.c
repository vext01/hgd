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

#include "client.h"
#include "config.h"
#include "hgd.h"
#include "net.h"
#include "user.h"
#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif

char			*user = NULL, *host = NULL, *password = NULL;
int			 port = HGD_DFL_PORT;
int			 sock_fd = -1;

SSL			*ssl = NULL;
SSL_METHOD		*method;
SSL_CTX			*ctx;
uint8_t			 crypto_pref = HGD_CRYPTO_PREF_IF_POSS;
uint8_t			 server_ssl_capable = 0;
uint8_t			 authenticated = 0;
uint8_t			 hud_refresh_speed = 5;
uint8_t			 colours_on = 1;

struct hgd_resp_err hgd_resp_errs[] = {
	{ "E_INT",		"Internal error" },
	{ "E_DENY",		"Access denied" },
	{ "E_FLSIZE",		"File size invalid" },
	{ "E_FLOOD",		"Flood protect triggered" },
	{ "E_NOPLAY",		"No track is playing" },
	{ "E_WRTRK",		"Wrong track" },
	{ "E_DUPVOTE",		"Duplicate vote" },
	{ "E_SSLAGN",		"Duplicate SSL negotiation" },
	{ "E_SSLNOAVAIL",	"SSL not available" },
	{ "E_INVCMD",		"Invalid command" },
	{ "E_SSLREQ",		"SSL required" },
	{ "E_SHTDWN",		"Server is going down" },
	{ "E_KICK",		"Client misbehaving" },
	{ "E_PERMNOCHG",	"Perms did not change" },
	{ "E_USREXIST",		"User already exists" },
	{ "E_USRNOEXIST",	"User does not exist" },
	{ 0,			0 }
};

int
hgd_client_edit_config()
{
	char			*path = NULL, *edit_cmd = NULL;
	char			*editor = getenv("EDITOR");
	int			 ret = HGD_FAIL;

	if (editor == NULL)
		editor = HGD_DFL_EDITOR;

	xasprintf(&path, "%s/%s/%s", getenv("HOME"),
	    HGD_USR_CFG_DIR, HGD_CLI_CFG);

	xasprintf(&edit_cmd, "%s %s", editor, path);

	if (system(edit_cmd) != 0)
		goto clean;

	ret = HGD_OK;
clean:
	free(edit_cmd);
	free(path);

	return (ret);
}
