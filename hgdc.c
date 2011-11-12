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

struct hgd_resp_err {
	char		*code;
	char		*meaning;
};

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

const char		*hgd_component = HGD_COMPONENT_HGDC;

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
uint8_t			 hud_max_items = 0;

/* protos */
int			 hgd_check_svr_response(char *resp, uint8_t x);

void
hgd_exit_nicely()
{
	uint8_t			ssl_ret = 0, i;

	if (!exit_ok)
		DPRINTF(HGD_D_ERROR,
		    "hgdc was interrupted or crashed - cleaning up");

	if (ssl) {
		/* as per SSL_shutdown() manual, we call at most twice */
		for (i = 0; i < 2; i++) {
			ssl_ret = SSL_shutdown(ssl);
			if (ssl_ret == 1)
				break;
		}

		if (ssl_ret != 1)
			DPRINTF(HGD_D_WARN, "couldn't shutdown SSL");

		SSL_free(ssl);
	}

	if (ctx)
		hgd_cleanup_ssl(&ctx);

	if (host)
		free(host);

	if (sock_fd > 0) {
		/* try to close connection */
#ifndef __APPLE__
		/*
		 * MAC OSX sockets behave differently!
		 *
		 * If one side of the socket closes, the connection in
		 * one direction, the corresponding socket on the other side
		 * will fail to shutdown(). This is hinted at in the python
		 * manual:
		 * http://docs.python.org/library/socket.html
		 *
		 * Long story short:
		 * On OSX the server will do the shutdown for us.
		 */
		if (shutdown(sock_fd, SHUT_RDWR) == -1)
			DPRINTF(HGD_D_WARN, "Couldn't shutdown socket");
#endif
		close(sock_fd);
	}

	HGD_CLOSE_SYSLOG();
	_exit(!exit_ok);
}

/*
 * see if the server supports encryption
 * return: 1 = yes, 0 = no, -1 = error
 */
int
hgd_negotiate_crypto()
{
	int			n_toks = 0, ret = HGD_OK;
	char			*first, *next;
	char			*ok_tokens[2] = {"", ""};

	if (crypto_pref == HGD_CRYPTO_PREF_NEVER)
		return (0);	/* fine, no crypto then */

	hgd_sock_send_line(sock_fd, NULL, "encrypt?");
	first = next = hgd_sock_recv_line(sock_fd, NULL);

	hgd_check_svr_response(next, 1);

	do {
		ok_tokens[n_toks] = strsep(&next, "|");
		n_toks++;
	} while ((n_toks < 2) && (next != NULL));

	if (strcmp(ok_tokens[1], "tlsv1") == 0) {
		server_ssl_capable = 1;
		DPRINTF(HGD_D_INFO, "Server supports %s crypto", ok_tokens[1]);
	}

	if ((!server_ssl_capable) && (crypto_pref == HGD_CRYPTO_PREF_ALWAYS)) {
		DPRINTF(HGD_D_ERROR,
		    "User forced crypto, but server is incapable");
		ret = HGD_FAIL;
	}

	free(first);

	return (ret);
}

int
hgd_encrypt(int fd)
{
	int			 ssl_res = 0;
	char			*ok_str = NULL;
	X509			*cert;

	/* XXX For semi-implemented certificate verification - FAO mex */
#if 0
	X509_NAME		*cert_name;
	EVP_PKEY		*public_key;
	BIO			*bio;
#endif
	hgd_sock_send_line(fd, NULL, "encrypt");

	if (hgd_setup_ssl_ctx(&method, &ctx, 0, 0, 0) != 0) {
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Setting up SSL_new");
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_new");
		return (HGD_FAIL);
	}

	ssl_res = SSL_set_fd(ssl, fd);
	if (ssl_res == 0) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_set_fd");
		return (HGD_FAIL);
	}

	ssl_res = SSL_connect(ssl);
	if (ssl_res != 1) {
		PRINT_SSL_ERR (HGD_D_ERROR, "SSL_connect");
		return (HGD_FAIL);
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		DPRINTF(HGD_D_ERROR, "could not get remote cert");
		exit (HGD_FAIL);
	}

/*
 * unfinished work on checking SSL certs.  Need to work out how to get the
 * hash from the cert to know where to write the cert to. XXX
 */
#if 0
	if(SSL_get_verify_result(ssl) != X509_V_OK)
	{
		PRINT_SSL_ERR ("SSL_connect");

		cert = SSL_get_peer_certificate(ssl);

		cert->
		/* PEM_write_x509(fp!,cert);- */

		return (-1);
	}
#endif
	ok_str = hgd_sock_recv_line(fd, ssl);
	hgd_check_svr_response(ok_str, 1);
	free(ok_str);

	DPRINTF(HGD_D_INFO, "SSL connection established");

	return (HGD_OK);
}

int
hgd_print_pretty_server_response(char *resp_line)
{
	char			*p;
	struct hgd_resp_err	*resp, *chosen = NULL;

	p = strchr(resp_line, '|');
	if (p == NULL) {
		DPRINTF(HGD_D_ERROR, "Unspecified server error reponse");
		return (HGD_FAIL);
	}

	p++;
	for (resp = hgd_resp_errs; resp->code != 0; resp++) {
		if (strcmp(p, resp->code) == 0) {
			chosen = resp;
			break;
		}
	}

	if (chosen == NULL) {
		DPRINTF(HGD_D_ERROR, "Unknown server error reponse");
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_ERROR,
	    "Server reponded with error '%s': %s", p, chosen->meaning);

	return (HGD_OK);
}

/*
 * if x == 1 you do not need to check the return value of this method as
 * hgd will have exited before this returns.
 */
int
hgd_check_svr_response(char *resp, uint8_t x)
{
	int			err = HGD_OK;
	char			*trunc = NULL;

	if (resp == NULL) {
		DPRINTF(HGD_D_ERROR, "failed to read server response");
		err = HGD_FAIL;
		goto clean;
	}

	if (hgd_debug) {
		trunc = xstrdup(resp);
		DPRINTF(HGD_D_DEBUG, "Check reponse '%s'", trunc);
		free(trunc);
	}

	if (strncmp(resp, "ok", 2) == 0) {
		/* great */
	} else if (strncmp(resp, "err", 3)) {
		DPRINTF(HGD_D_ERROR, "Malformed server response");
	} else {
		/* we got an 'err' */
		hgd_print_pretty_server_response(resp);
		err = HGD_FAIL;
	}

clean:
	/* frees reposonse on error and exit */
	if ((err == HGD_FAIL) && (x)) {
		free(resp);
		hgd_exit_nicely();
	}

	return (err);
}

int
hgd_client_login(int fd, SSL *ssl, char *username)
{
	char			*resp, *user_cmd, pass[HGD_MAX_PASS_SZ];
	int			 login_ok = -1;
	char			*prompt;

	if (password == NULL) {
		xasprintf(&prompt, "Password for %s@%s: ", user, host);
		if (readpassphrase(prompt, pass, HGD_MAX_PASS_SZ,
		    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Problem reading password from user");
			memset(pass, 0, HGD_MAX_PASS_SZ);
			free(prompt);
			return (HGD_FAIL);
		}
		free(prompt);
	} else {
		strncpy(pass, password, HGD_MAX_PASS_SZ);
		if (HGD_MAX_PASS_SZ > 0)
			pass[HGD_MAX_PASS_SZ-1] = '\0';
	}

	/* send password */
	xasprintf(&user_cmd, "user|%s|%s", username, pass);
	hgd_sock_send_line(fd, ssl, user_cmd);
	memset(pass, 0, HGD_MAX_PASS_SZ);
	free(user_cmd);

	resp = hgd_sock_recv_line(fd, ssl);
	login_ok = hgd_check_svr_response(resp, 0);

	free(resp);

	if (login_ok == HGD_OK) {
		authenticated = 1;
		DPRINTF(HGD_D_DEBUG, "Identified as %s", user);
	} else
		DPRINTF(HGD_D_WARN, "Login as %s failed", user);

	return (login_ok);
}

int
hgd_setup_socket()
{
	struct sockaddr_in	addr;
	char*			resp;
	struct hostent		*he;
	int			sockopt = 1, ret = HGD_OK;

	DPRINTF(HGD_D_DEBUG, "Connecting to %s", host);

	/* if they gave a hostname, we look up the IP */
	if (!hgd_is_ip_addr(host)) {
		DPRINTF(HGD_D_DEBUG, "Looking up host '%s'", host);
		he = gethostbyname(host);
		if (he == NULL) {
			DPRINTF(HGD_D_ERROR,
			    "Failure in hostname resolution: '%s'", host);
			ret = HGD_FAIL;
			goto clean;
		}

		free(host);
		host = xstrdup(
		    inet_ntoa( *(struct in_addr*)(he->h_addr_list[0])));
		DPRINTF(HGD_D_DEBUG, "Found IP %s", host);
	}

	DPRINTF(HGD_D_DEBUG, "Connecting to IP %s:%d", host, port);

	/* set up socket address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		DPRINTF(HGD_D_ERROR, "can't make socket: %s", SERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
		    &sockopt, sizeof(sockopt)) < 0) {
		DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sock_fd);
		DPRINTF(HGD_D_ERROR, "Can't connect to %s", host);
		ret = HGD_FAIL;
		goto clean;
	}

	/* expect a hello message */
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "Connected to %s", host);

	/* identify ourselves */
	if (user == NULL) {
		/* If the user did not set their name use thier system login */
		user = getenv("USER");
	}
	if (user == NULL) {
		DPRINTF(HGD_D_ERROR, "can't get username");
		ret = HGD_FAIL;
		goto clean;
	}

	hgd_negotiate_crypto();
	if ((server_ssl_capable) && (crypto_pref != HGD_CRYPTO_PREF_NEVER)) {
		if (hgd_encrypt(sock_fd) != HGD_OK) {
			ret = HGD_FAIL;
			goto clean;
		}
	}

	/* annoying error message for those too lazy to set up crypto */
	if (ssl == NULL)
		DPRINTF(HGD_D_WARN, "Connection is not encrypted");

clean:
	return (ret);
}

void
hgd_usage()
{
	printf("Usage: hgdc [opts] command [args]\n\n");
	printf("  Commands include:\n");
	printf("    hud\t\t\tHeads up display\n");
	printf("    id\t\t\tShow user account details and vote info\n");
	printf("    ls\t\t\tShow playlist\n");
	printf("    np\t\t\tNow playing\n");
	printf("    q <file1> [...]\tQueue track(s)\n");
	printf("    vo\t\t\tVote-off current track\n");

	printf("\n  Admin Commands include:\n");
	printf("    pause\t\t\tPause the current song\n");
	printf("    skip\t\t\tSkip the current song\n");
	printf("    user-add <user> [password]\tAdd a user\n");
	printf("    user-del <user>\t\tRemove a user\n");
	printf("    user-list\t\t\tList Users\n");
	printf("    user-mkadmin <user>\t\tGrant user admin rights\n");
	printf("    user-noadmin <user>\t\tRevoke user admin rights\n");

	printf("\n  Options include:\n");
	printf("    -A\t\t\tColours off\n");
	printf("    -a\t\t\tColours on\n");
#ifdef HAVE_LIBCONFIG
	printf("    -c\t\t\tSet config location\n");
#endif
	printf("    -E\t\t\tRefuse to use encryption\n");
	printf("    -e\t\t\tForce encryption\n");
	printf("    -h\t\t\tShow this message and exit\n");
	printf("    -m <num>\t\tMax num items to show in playlist\n");
	printf("    -p <port>\t\tSet connection port\n");
	printf("    -r <secs>\t\trefresh rate (only in hud mode)\n");
	printf("    -s <host/ip>\tSet connection address\n");
	printf("    -u <username>\tSet username\n");
	printf("    -x <level>\t\tSet debug level (0-3)\n");
	printf("    -v\t\t\tShow version and exit\n");
}

int
hgd_queue_track(char *filename)
{
	FILE			*f;
	struct stat		st;
	ssize_t			written = 0, fsize, chunk_sz;
	char			chunk[HGD_BINARY_CHUNK];
	char			*q_req = 0, *resp1 = 0, *resp2 = 0;
	char			 stars_buf[81], *trunc_filename = 0;
	int			 iters = 0, barspace, percent, ret = HGD_FAIL;
	float			 n_stars;

	/* maximum length of filename in progress bar */
	trunc_filename = xstrdup(basename(filename));
	hgd_truncate_string(trunc_filename, 40);

	DPRINTF(HGD_D_INFO, "Uploading file '%s'", filename);

	if (stat(filename, &st) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't stat '%s'", filename);
		ret = HGD_FAIL;
		goto clean;
	}

	if (st.st_mode & S_IFDIR) {
		DPRINTF(HGD_D_ERROR, "Can't upload directories");
		ret = HGD_FAIL;
		goto clean;
	}

	fsize = st.st_size;

	/* send request to upload */
	xasprintf(&q_req, "q|%s|%d", filename, fsize);
	hgd_sock_send_line(sock_fd, ssl, q_req);

	/* check we are allowed */
	resp1 = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp1, 0) == HGD_FAIL)
		goto clean;

	DPRINTF(HGD_D_DEBUG, "opening '%s' for reading", filename);
	f = fopen(filename, "r");
	if (f == NULL) {
		DPRINTF(HGD_D_ERROR, "fopen %s: %s", filename, SERROR);
		ret = HGD_FAIL;
		goto clean;
	}

	/* prepare progress bar */
	barspace =  (float) (HGD_TERM_WIDTH - strlen(
	    basename(trunc_filename)) - 2) - 7;
	memset(stars_buf, ' ', HGD_TERM_WIDTH);
	stars_buf[HGD_TERM_WIDTH] = 0;

	/*
	 * start sending the file
	 */
	written = 0;
	while (written != fsize) {

		/* update progress bar */
		if ((iters % 50 == 0) && (hgd_debug <= 1)) {
			percent = (float) written/fsize * 100;
			n_stars = barspace * ((float) written/fsize) + 1;
			memset(stars_buf, '*', n_stars);

			/* progress bar caps */
			stars_buf[0] = '|';
			stars_buf[barspace - 1] = '|';
			stars_buf[barspace] = 0;

			printf("\r%s: %s %3d%%",
			    trunc_filename, stars_buf, percent);
			fflush(stdout);
		}
		iters++;

		if (fsize - written < HGD_BINARY_CHUNK)
			chunk_sz = fsize - written;
		else
			chunk_sz = HGD_BINARY_CHUNK;

		if (fread(chunk, chunk_sz, 1, f) != 1) {
			DPRINTF(HGD_D_WARN, "Retrying fread");
			continue;
		}

		hgd_sock_send_bin(sock_fd, ssl, chunk, chunk_sz);

		written += chunk_sz;
		DPRINTF(HGD_D_DEBUG, "Progress %d/%d bytes",
		    (int)  written, (int) fsize);
	}

	if (hgd_debug <= 1) {
		memset(stars_buf, ' ', HGD_TERM_WIDTH);

		hgd_set_line_colour(ANSI_GREEN);
		printf("\r%s\r%s: OK\n", stars_buf, basename(trunc_filename));
		hgd_set_line_colour(ANSI_WHITE);
	}

	fclose(f);

	resp2 = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp2, 0) == HGD_FAIL) {
		ret = HGD_FAIL;
		goto clean;
	}

	DPRINTF(HGD_D_INFO, "Transfer complete");

	ret = HGD_OK;
clean:
	if (trunc_filename)
		free(trunc_filename);
	if (resp1)
		free(resp1);
	if (resp2)
		free(resp2);
	if (q_req)
		free(q_req);

	return (ret);
}

/* upload and queue a file to the playlist */
int
hgd_req_queue(int n_args, char **args)
{
	int			tnum, ret = HGD_OK;

	DPRINTF(HGD_D_DEBUG, "Will queue %d tracks", n_args);

	/* one iteration per track which will be uploaded */
	for (tnum = 0; tnum < n_args; tnum++)
		if (hgd_queue_track(args[tnum]) != HGD_OK) {
			ret = HGD_FAIL;
		}

	if (ret != HGD_OK)
		DPRINTF(HGD_D_INFO, "Some tracks failed to upload");
	else
		DPRINTF(HGD_D_INFO, "Finished uploading tracks");

	return (ret);
}

#define HGD_NUM_TRACK_FIELDS		14
int
hgd_print_track(char *resp, uint8_t first)
{
	int			n_toks = 0, i, ret = HGD_OK;
	char			*tokens[HGD_NUM_TRACK_FIELDS];

	do {
		tokens[n_toks] = xstrdup(strsep(&resp, "|"));
	} while ((n_toks++ < HGD_NUM_TRACK_FIELDS) && (resp != NULL));

	if (n_toks == HGD_NUM_TRACK_FIELDS) {

		if (first)
			hgd_set_line_colour(ANSI_GREEN);
		else
			hgd_set_line_colour(ANSI_RED);

		printf(" [ #%04d queued by '%s' ]\n",
		    atoi(tokens[0]), tokens[4]);

		printf("   Filename: '%s'\n",
		    hgd_truncate_string(tokens[1],
		    HGD_TERM_WIDTH - strlen("   Filename: ''")));

		printf("   Artist:   ");
		if (strcmp(tokens[2], "") != 0)
			printf("'%s'\n", hgd_truncate_string(tokens[2],
			    HGD_TERM_WIDTH - strlen("   Artist:   ''")));
		else
			printf("<unknown>\n");

		printf("   Title:    ");
		if (strcmp(tokens[3], "") != 0)
			printf("'%s'\n",
			    hgd_truncate_string(tokens[3],
			    HGD_TERM_WIDTH - strlen("   Title:    ''")));
		else
			printf("<unknown>\n");

		/* thats it for compact entries */
		if (!first)
			goto skip_full;

		printf("   Album:    ");
		if (strcmp(tokens[5], "") != 0)
			printf("'%s'\n", hgd_truncate_string(tokens[5],
			    HGD_TERM_WIDTH - strlen("   Album:    ''")));
		else
			printf("<unknown>\n");

		printf("   Genre:    ");
		if (strcmp(tokens[6], "") != 0)
			printf("'%s'\n", hgd_truncate_string(tokens[6],
			    HGD_TERM_WIDTH - strlen("   Genre:    ''")));
		else
			printf("<unknown>\n");

		printf("   Year:     ");
		if (strcmp(tokens[11], "0") != 0)
			printf("'%s'\n", hgd_truncate_string(tokens[11],
			    HGD_TERM_WIDTH - strlen("   Year:     ''")));
		else
			printf("<unknown>\n");

		/* audio properties all on one line */
		printf("   Audio:    ");

		if (atoi(tokens[7]) != 0)
			printf("%4ss", tokens[7]);
		else
			printf("%4ss", "????");

		if (atoi(tokens[9]) != 0)
			printf("   %5shz", tokens[9]);
		else
			printf("   %5shz", "?");

		if (atoi(tokens[8]) != 0)
			printf("   %3skbps", tokens[8]);
		else
			printf("   %3skbps", "?");

		if (atoi(tokens[10]) != 0)
			printf("   %s channels\n", tokens[10]);
		else
			printf("   %s channels\n", "?");

		/* vote off info */
		printf("   Votes needed to skip:    %s\n",
		    atoi(tokens[12]) == 0 ? "none" : tokens[12]);

		switch (atoi(tokens[13])) {
		case 0:
			printf("   You may vote off this track.\n");
			break;
		case 1:
			hgd_set_line_colour(ANSI_CYAN);
			printf("   You HAVE voted-off this track.\n");
			break;
		case -1:
			printf("   Could not auhtenticate. Log in to enable vote-off functionality.\n");
			break;
		default:
			DPRINTF(HGD_D_ERROR, "Bogus 'has_voted' field");
			ret = HGD_FAIL;
		};
skip_full:
		hgd_set_line_colour(ANSI_WHITE);

	} else {
		DPRINTF(HGD_D_ERROR, "Wrong number of tokens from server");
		ret = HGD_FAIL;
	}

	for (i = 0; i < n_toks; i ++)
		free(tokens[i]);

	return (ret);
}

void
hgd_hline()
{
	int			i;

	for (i = 0; i < HGD_TERM_WIDTH; i++)
		printf("-");
	printf("\n");
}

int
hgd_req_vote_off(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

	hgd_sock_send_line(sock_fd, ssl, "vo");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Vote off failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_playlist(int n_args, char **args)
{
	char			*resp, *track_resp, *p;
	int			n_items, i;

	(void) args;
	(void) n_args;

	/*
	 * we try to log in to get info about vote-off. If it fails,
	 * so be it. We just won't show any vote info for the user.
	 */
	if (!authenticated)
		hgd_client_login(sock_fd, ssl, user);

	hgd_sock_send_line(sock_fd, ssl, "ls");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		free(resp);
		return (HGD_FAIL);
	}

	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		DPRINTF(HGD_D_ERROR, "didn't find a argument separator");
		free(resp);
		return (HGD_FAIL);
	}

	n_items = atoi(++p);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "expecting %d items in playlist", n_items);
	for (i = 0; i < n_items; i++) {
		track_resp = hgd_sock_recv_line(sock_fd, ssl);

		if (hud_max_items == 0 || hud_max_items > i) {
			hgd_hline();
			hgd_print_track(track_resp, i == 0);
		}

		free(track_resp);
	}

	if (n_items)
		hgd_hline();
	else
		printf("Nothing to play!\n");

	return (HGD_OK);
}

/*
 * Heads up display mode
 * May make this more spctacular at some stage...
 */
int
hgd_req_hud(int n_args, char **args)
{
	int			status;

	(void) args;
	(void) n_args;

	/* pretty clunky ;) */
	while (1) {
		status = system("clear");
		if (status != 0)
			DPRINTF(HGD_D_WARN, "clear screen failed");

		hgd_set_line_colour(ANSI_YELLOW);
		printf("HGD Server @ %s -- Playlist:\n\n", host);
		hgd_set_line_colour(ANSI_WHITE);

		if (hgd_req_playlist(0, NULL) != HGD_OK)
			return (HGD_FAIL);

		sleep(hud_refresh_speed);
	}

	return (HGD_OK);
}

int
hgd_req_skip(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

	hgd_sock_send_line(sock_fd, ssl, "skip");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Skip failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_pause(int n_args, char **args)
{
	char			*resp;

	(void) args;
	(void) n_args;

	hgd_sock_send_line(sock_fd, ssl, "pause");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Pause failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_add(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-add|%s|%s", args[0], args[1]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "Add user failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_add_prompt(int n_args, char **args)
{
	char	*pass = calloc (HGD_MAX_PASS_SZ, sizeof(char));
	char	*args2[2];

	(void) n_args;

	hgd_readpassphrase_confirmed(pass, "New user's password: ");
	args2[0] = args[0];
	args2[1] = pass;

	return hgd_req_user_add(2, args2);
}

int
hgd_req_user_list(int n_args, char **args)
{
	char			*resp, *permstr;
	char			*msg, *p;
	int			n_items, i;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-list");
	hgd_sock_send_line(sock_fd, ssl, msg);
	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "list users failed");
		free(resp);
		return (HGD_FAIL);
	}

	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		DPRINTF(HGD_D_ERROR, "didn't find a argument separator");
		free(resp);
		return (HGD_FAIL);
	}

	n_items = atoi(++p);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "expecting %d users in list", n_items);

	for (i = 0; i < n_items; i++) {
		DPRINTF(HGD_D_DEBUG, "getting user %d", i);
		resp = hgd_sock_recv_line(sock_fd, ssl);

		if ((p = strchr(resp, '|')) == NULL) {
			DPRINTF(HGD_D_WARN, "could not find perms field");
		} else {
			*p++ = 0;
			hgd_gen_perms_str(atoi(p), &permstr);
			printf("%-20s %s\n", resp, permstr);
			free(permstr);
		}

		free(resp);
	}

	return (HGD_OK);
}

int
hgd_req_user_del(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-del|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "del user failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}


int
hgd_req_user_mkadmin(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-mkadmin|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "mkadmin failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_user_noadmin(int n_args, char **args)
{
	char			*resp;
	char			*msg;

	(void) args;
	(void) n_args;

	xasprintf(&msg, "user-noadmin|%s", args[0]);

	hgd_sock_send_line(sock_fd, ssl, msg);

	free(msg);

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL) {
		DPRINTF(HGD_D_ERROR, "noadmin failed");
		free(resp);
		return (HGD_FAIL);
	}

	free(resp);
	return (HGD_OK);
}

int
hgd_req_np(int n_args, char **args)
{
	char			*resp = NULL, *p;
	int			 ret = HGD_FAIL;

	(void) n_args;
	(void) args;

	/*
	 * we try to log in to get info about vote-off. If it fails,
	 * so be it. We just won't show any vote info for the user.
	 */
	if (!authenticated)
		hgd_client_login(sock_fd, ssl, user);

	hgd_sock_send_line(sock_fd, ssl, "np");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL)
		return (HGD_FAIL);

	/* find 1st | */
	p = strchr(resp, '|');
	if (!p) {
		DPRINTF(HGD_D_ERROR, "Failed to find separator1");
		goto fail;
	}

	/* check that something is even playing */
	if (*(p+1) != '1')
		printf("Nothing playing right now.\n");
	else {
		/* find 2nd | */
		p = strchr(p + 1, '|');
		if (!p) {
			DPRINTF(HGD_D_ERROR, "Failed to find separator2");
			goto fail;
		}
		hgd_print_track(p + 1, 1);
	}

	ret = HGD_OK;
fail:
	if (resp)
		free(resp);

	return (ret);
}

int
hgd_req_id(int n_args, char **args)
{
	char			*resp = NULL, *toks[4] = {"", "", "", ""};
	char			*next, *perms_str = NULL;
	int			 ret = HGD_FAIL, n_toks = 0;

	(void) n_args;
	(void) args;

	hgd_sock_send_line(sock_fd, ssl, "id");
	resp = next = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == HGD_FAIL)
		goto fail;

	do {
		toks[n_toks] = strsep(&next, "|");
		n_toks++;
	} while ((n_toks < 4) && (next != NULL));

	/* build permissions string, if we add more this changes */
	if (atoi(toks[2]) & HGD_AUTH_ADMIN)
		perms_str = "ADMIN";
	else
		perms_str = "NONE";

	printf("  You are %s, permissions: %s, voted: %d\n",
	    toks[1], perms_str, atoi(toks[3]));

	ret = HGD_OK;
fail:
	if (resp)
		free(resp);

	return (ret);
}

/* lookup for request despatch */
struct hgd_req_despatch req_desps[] = {
/*	cmd,		n_args,	need_auth,	handler,		varargs */
	{"id",		0,	1,		hgd_req_id,		0},
	{"ls",		0,	0,		hgd_req_playlist,	0},
	{"hud",		0,	0,		hgd_req_hud,		0},
	{"vo",		0,	1,		hgd_req_vote_off,	0},
	{"np",		0,	0,		hgd_req_np,		0},
	{"q",		1,	1,		hgd_req_queue,		1},
	/* play control */
	{"skip",	0,	1,		hgd_req_skip,		0},
	{"pause",	0,	1,		hgd_req_pause,		0},
	/* users */
	{"user-add",	2,	1,		hgd_req_user_add,	0},
	{"user-add",	1,	1,		hgd_req_user_add_prompt,0},
	{"user-list",	0,	1,		hgd_req_user_list,	0},
	{"user-del",	1,	1,		hgd_req_user_del,	0},
	{"user-mkadmin",1,	1,		hgd_req_user_mkadmin,	0},
	{"user-noadmin",1,	1,		hgd_req_user_noadmin,	0},
	{NULL,		0,	0,		NULL,			0} /* end */
};

/*
 * check protocol version is correct
 */
int
hgd_check_svr_proto()
{
	char			*v, *resp = NULL;
	int			 major = -1, minor = -1, ret = HGD_OK;
	char			*split = "|";
	char			*saveptr1;

	hgd_sock_send_line(sock_fd, ssl, "proto");
	resp = hgd_sock_recv_line(sock_fd, ssl);

	if (hgd_check_svr_response(resp, 0) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Could not check server proto version");
		ret = HGD_FAIL;
		goto clean;
	}

	v = strtok_r(resp, split, &saveptr1);
	(void) v;

	/* major */
	v = strtok_r(NULL, split, &saveptr1);
	if (v == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not find protocol MAJOR version");
		ret = HGD_FAIL;
		goto clean;
	}

	major = atoi(v);

	/* minor */
	v = strtok_r(NULL, split, &saveptr1);
	if (v == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not find protocol MINOR version");
		ret = HGD_FAIL;
		goto clean;
	}

	minor = atoi(v);

	if (major == HGD_PROTO_VERSION_MAJOR && minor >= HGD_PROTO_VERSION_MINOR) {
		if (minor > HGD_PROTO_VERSION_MINOR) {
			DPRINTF(HGD_D_INFO, "Server is running a newer minor version"
			    "of the server.Server=%d,%d, Client=%d,%d", major, minor,
			    HGD_PROTO_VERSION_MAJOR, HGD_PROTO_VERSION_MINOR);
		}
	} else {
		DPRINTF(HGD_D_ERROR, "Protocol mismatch: "
		    "Server=%d,%d, Client=%d,%d", major, minor,
		    HGD_PROTO_VERSION_MAJOR, HGD_PROTO_VERSION_MINOR);
		ret = HGD_FAIL;
		goto clean;
	}


	DPRINTF(HGD_D_DEBUG, "Protocol version matches server");

clean:
	if (resp)
		free(resp);

	return (ret);
}

/* parse command line args */
int
hgd_exec_req(int argc, char **argv)
{
	struct hgd_req_despatch		*desp, *correct_desp = NULL;

	DPRINTF(HGD_D_DEBUG, "Try to execute a '%s' command with %d args",
	    argv[0], argc - 1);

	if (argc == 0) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
		return (HGD_FAIL); /* UNREACH, to keep clang-sa happy */
	}

	for (desp = req_desps; desp->req != NULL; desp++) {
		if (strcmp(desp->req, argv[0]) != 0)
			continue;

		if ((desp->varargs) && (argc - 1 < desp->n_args))
			continue;
		else if ((!desp->varargs) && (argc - 1 != desp->n_args))
			continue;

		correct_desp = desp; /* found it */
		break;
	}

	if (correct_desp == NULL) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
		return (HGD_FAIL); /* UNREACH, to keep clang-sa happy */
	}

	/* once we know that the hgdc is used properly, open connection */
	if (hgd_setup_socket() != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Cannot setup socket");
		return (HGD_FAIL);
	}

	/* check protocol matches the server before we continue */
	if (hgd_check_svr_proto() != HGD_OK)
		return (HGD_FAIL);

	DPRINTF(HGD_D_DEBUG, "Despatching request '%s'", correct_desp->req);
	if ((!authenticated) && (correct_desp->need_auth)) {
		if (hgd_client_login(sock_fd, ssl, user) != HGD_OK) {
			return (HGD_FAIL);
		}
	}

	correct_desp->handler(argc - 1, &argv[1]);

	return (HGD_OK);
}

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * see hgd-playd.c for how to remove need for stat.
	 */
	config_t		 cfg, *cf;
	int			 ret = HGD_OK;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		return (HGD_OK);
	}

	hgd_cfg_c_colours(cf, &colours_on);
	hgd_cfg_crypto(cf, "hgdc", &crypto_pref);
	hgd_cfg_c_maxitems(cf, &hud_max_items);
	hgd_cfg_c_hostname(cf, &host);
	hgd_cfg_c_port(cf, &port);
	hgd_cfg_c_password(cf, &password, *config_locations);
	hgd_cfg_c_refreshrate(cf, &hud_refresh_speed);
	hgd_cfg_c_username(cf, &user);
	hgd_cfg_c_debug(cf, &hgd_debug);

	config_destroy(cf);
	return (ret);
#else
	return(HGD_OK);
#endif
}

int
main(int argc, char **argv)
{
	char			*resp, *xdg_config_home;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2, ch;

	/* open syslog as soon as possible */
	HGD_INIT_SYSLOG();

	host = xstrdup(HGD_DFL_HOST);
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_CLI_CFG );

	xdg_config_home =  getenv("XDG_CONFIG_HOME");
	if (xdg_config_home == NULL) {
		xasprintf(&config_path[2], "%s%s", getenv("HOME"),
		    HGD_USR_CFG_DIR HGD_CLI_CFG);
	} else {
		xasprintf(&config_path[2], "%s%s",
		    xdg_config_home , "/hgd" HGD_CLI_CFG);
	}

	/*
	 * Need to do getopt twice because x and c need to be done before
	 * reading the config
	 */
	while ((ch = getopt(argc, argv, "aAc:Eehm:p:r:s:u:vx:")) != -1) {
		switch (ch) {
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
		case 'c':
			if (num_config < 3) {
				num_config++;
				DPRINTF(HGD_D_DEBUG, "added config %d %s",
				    num_config, optarg);
				config_path[num_config] = xstrdup(optarg);
			} else {
				DPRINTF(HGD_D_WARN,
				    "Too many config files specified");
				hgd_exit_nicely();
			}
			break;
		default:
			break; /* catch badness on next getopt */
		}
	}

	hgd_read_config(config_path + num_config);

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}


	RESET_GETOPT();

	while ((ch = getopt(argc, argv, "aAc:Eehm:p:r:s:u:vx:")) != -1) {
		switch (ch) {
		case 'a':
			DPRINTF(HGD_D_DEBUG, "ANSI colours on");
			colours_on = 1;
			break;
		case 'A':
			DPRINTF(HGD_D_DEBUG, "ANSI colours off");
			colours_on = 0;
			break;
		case 'c':
			break; /* already handled */
		case 'e':
			DPRINTF(HGD_D_DEBUG, "Client will insist upon cryto");
			crypto_pref = HGD_CRYPTO_PREF_ALWAYS;
			break;
		case 'E':
			DPRINTF(HGD_D_DEBUG, "Client will insist upon "
			   " no crypto");
			crypto_pref = HGD_CRYPTO_PREF_NEVER;
			break;
		case 'm':
			hud_max_items = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set max playlist items to %d",
			    hud_max_items);
			break;
		case 's':
			DPRINTF(HGD_D_DEBUG, "Set server to %s", optarg);
			free(host);
			host = xstrdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "set port to %d", port);
			break;
		case 'r':
			hud_refresh_speed = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set hud refresh rate to %d",
			    hud_refresh_speed);
			break;
		case 'u':
			free(user);
			user = strdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set username to %s", user);
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			DPRINTF(HGD_D_DEBUG, "set debug to %d", atoi(optarg));
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			break; /* already set but over-rideable */
		case 'h':
		default:
			hgd_usage();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		};
	}

	argc -= optind;
	argv += optind;

	/* secure mask */
	umask(~S_IRWXU);

	/* do whatever the user wants */
	if (hgd_exec_req(argc, argv) == HGD_OK)
		exit_ok = 1;
	else {
		exit_ok = 0;
		goto kthxbye;
	}

	/* try to sign off */
	hgd_sock_send_line(sock_fd, ssl, "bye");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	exit_ok = 1;

kthxbye:
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
