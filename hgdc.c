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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "hgd.h"

#define PRINT_SSL_ERR							\
	do {								\
		char error[255];					\
		unsigned long err;					\
		err = ERR_get_error();					\
		ERR_error_string_n(err, error, sizeof(error));		\
		printf("SSL_CTX_new: %s\n", error);			\
	} while(0)

char			*user, *host = "127.0.0.1";
int			 will_encrypt = 0;
int			 port = HGD_DFL_PORT;
int			 sock_fd = -1;

SSL			*ssl = NULL;
const SSL_METHOD	*method;
SSL_CTX			*ctx;

/* protos */
int			 hgd_check_svr_response(char *resp, uint8_t x);

void
hgd_exit_nicely()
{
	/* XXX cleanup ssl */

	if (!exit_ok)
		DPRINTF(HGD_D_INFO,
		    "hgdc was interrupted or crashed - cleaning up");

	if (sock_fd > 0) {
		/* try to close connection */
		if (shutdown(sock_fd, SHUT_RDWR) == -1)
			DPRINTF(HGD_D_WARN, "Couldn't shutdown socket");
		close(sock_fd);
	}

	_exit(!exit_ok);
}

int
hgd_encrypt(int fd)
{
	int		 ssl_res = 0;
	char		*ok_str = NULL;

	hgd_sock_send_line(fd, NULL, "encrypt");

	/* XXX this block can probably be moved so its done once */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv2_client_method();

	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		PRINT_SSL_ERR;
		return -1;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		PRINT_SSL_ERR;
		return -1;
	}

	ssl_res = SSL_set_fd(ssl, fd);
	if (ssl_res == 0) {
		PRINT_SSL_ERR;
		return -1;
	}

	ssl_res = SSL_connect(ssl);
	if (ssl_res != 1) {
		PRINT_SSL_ERR;
		return -1;
	}

	ok_str = hgd_sock_recv_line(fd, ssl);
	hgd_check_svr_response(ok_str, 1);
	free(ok_str);

	DPRINTF(HGD_D_INFO, "SSL established");

	return (0);
}

int
hgd_check_svr_response(char *resp, uint8_t x)
{
	int			len, err = 0;
	char			*trunc = NULL;

	if (resp == NULL) {
		DPRINTF(HGD_D_ERROR, "failed to read server response, "
		    "did the server die?");
		hgd_exit_nicely();
	}

	len = strlen(resp);

	if (hgd_debug) {
		trunc = strdup(resp);
		DPRINTF(HGD_D_DEBUG, "Check reponse '%s'", trunc);
		free(trunc);
	} else
		trunc = trunc; /* silence compiler */

	if (len < 2) {
		DPRINTF(HGD_D_ERROR, "Malformed server response");
		err = -1;
	} else if ((resp[0] != 'o') || (resp[1] != 'k')) {
		if (len < 5)
			DPRINTF(HGD_D_ERROR, "Malformed server response");
		else
			DPRINTF(HGD_D_ERROR, "Failure: %s", &resp[4]);
		err = -1;
	}

	if ((err == -1) && (x)) {
		free(resp);
		hgd_exit_nicely();
	}

	return err;
}

int
hgd_client_login(int fd, SSL* ssl, char* username)
{
	char			*resp, *user_cmd;
	int			 login_ok = -1;

	xasprintf(&user_cmd, "user|%s", username);
	hgd_sock_send_line(fd, ssl, user_cmd);
	free(user_cmd);

	resp = hgd_sock_recv_line(fd, ssl);
	login_ok = hgd_check_svr_response(resp, 0);

	free(resp);

	if (login_ok == 0)
		DPRINTF(HGD_D_DEBUG, "Identified as %s", user);
	else
		DPRINTF(HGD_D_WARN, "Login as %s failed", user);

	return (login_ok);
}

void
hgd_setup_socket()
{
	struct sockaddr_in	addr;
	char*			resp;
	struct hostent		*he;
	int			sockopt = 1;

	DPRINTF(HGD_D_DEBUG, "Connecting to %s", host);

	/* if they gave a hostname, we look up the IP */
	if (!hgd_is_ip_addr(host)) {
		DPRINTF(HGD_D_DEBUG, "Looking up host '%s'", host);
		he = gethostbyname(host);
		if (he == NULL) {
			DPRINTF(HGD_D_ERROR,
			    "Failiure in hostname resolution: '%s'", host);
			hgd_exit_nicely();
		}

		host = inet_ntoa( *(struct in_addr*)(he->h_addr_list[0]));
		DPRINTF(HGD_D_DEBUG, "Found IP %s", host);
	}

	DPRINTF(HGD_D_DEBUG, "Connecting to IP %s", host);

	/* set up socket address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		DPRINTF(HGD_D_ERROR, "can't make socket: %s", SERROR);
		hgd_exit_nicely();
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
		    &sockopt, sizeof(sockopt)) < 0) {
		DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sock_fd);
		DPRINTF(HGD_D_ERROR, "Can't connect to %s", host);
		hgd_exit_nicely();
	}

	/* expect a hello message */
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "Connected to %s", host);

	/* identify ourselves */
	user = getenv("USER");
	if (user == NULL) {
		DPRINTF(HGD_D_ERROR, "can't get username");
		hgd_exit_nicely();
	}

	if (will_encrypt) {
		/* XXX check return value of this */
		hgd_encrypt(sock_fd);
	}

	/* XXX check return */
	hgd_client_login(sock_fd, ssl, user);
}



void
hgd_usage()
{
	printf("Usage: hgdc [opts] command [args]\n\n");
	printf("  Commands include:\n");
	printf("    hud\t\t\tHeads up display\n");
	printf("    q <filename>\tQueue a track\n");
	printf("    vo\t\t\tVote-off current track\n");
	printf("    ls\t\t\tShow playlist\n\n");
	printf("  Options include:\n");
	printf("    -h\t\tShow this message and exit\n");
	printf("    -p port\t\tSet connection port\n");
	printf("    -s host/ip\t\tSet connection address\n");
	printf("    -x level\t\tSet debug level (0-3)\n");
	printf("    -v\t\t\tShow version and exit\n");
}

/* upload and queue a file to the playlist */
int
hgd_req_queue(char **args)
{
	FILE			*f;
	struct stat		st;
	ssize_t			written = 0, fsize, chunk_sz;
	char			chunk[HGD_BINARY_CHUNK], *filename = args[0];
	char			*q_req, *resp;

	DPRINTF(HGD_D_DEBUG, "Will queue '%s'", args[0]);

	if (stat(filename, &st) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't stat '%s'", filename);
		hgd_exit_nicely();
	}

	if (st.st_mode & S_IFDIR) {
		DPRINTF(HGD_D_ERROR, "Can't upload directories");
		hgd_exit_nicely();
	}

	fsize = st.st_size;

	/* send request to upload */
	xasprintf(&q_req, "q|%s|%d", filename, fsize);
	hgd_sock_send_line(sock_fd, ssl, q_req);
	free(q_req);

	/* check we are allowed */
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}
	free(resp);

	DPRINTF(HGD_D_DEBUG, "opening '%s' for reading", filename);
	f = fopen(filename, "r");
	if (f == NULL) {
		DPRINTF(HGD_D_ERROR, "fopen %s: %s", filename, SERROR);
		return -1;
	}

	while (written != fsize) {
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

	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}

	DPRINTF(HGD_D_DEBUG, "Transfer complete");
	free(resp);

	return (0);
}

void
hgd_print_track(char *resp)
{
	int			n_toks = 0, i;
	char			*tokens[3] = {NULL, NULL, NULL};

	do {
		tokens[n_toks] = strdup(strsep(&resp, "|"));
	} while ((n_toks++ < 3) && (resp != NULL));

	if (n_toks == 3)
		printf(" [ #%04d ] '%s' from '%s'\n",
		    atoi(tokens[0]), tokens[1], tokens[2]);
	else
		fprintf(stderr,
		    "%s: wrong number of tokens from server\n",
		    __func__);

	for (i = 0; i < n_toks; i ++)
		free(tokens[i]);
}

void
hgd_hline()
{
	int			i;

	for (i = 0; i < 78; i ++)
		printf("-");
	printf("\n");
}

int
hgd_req_vote_off(char **args)
{
	char			*resp;

	args = args; /* sssh */

	hgd_sock_send_line(sock_fd, ssl, "vo");

	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 0);

	return (0);
}

int
hgd_req_playlist(char **args)
{
	char			*resp, *track_resp, *p;
	int			n_items, i;

	args = args; /* shhh */

	hgd_sock_send_line(sock_fd, ssl, "ls");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}

	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		DPRINTF(HGD_D_ERROR, "didn't find a argument separator");
		free(resp);
		return -1;
	}

	n_items = atoi(++p);
	free(resp);

	DPRINTF(HGD_D_DEBUG, "expecting %d items in playlist", n_items);
	for (i = 0; i < n_items; i++) {
		track_resp = hgd_sock_recv_line(sock_fd, ssl);
		if (i == 0) {
			hgd_hline();
			hgd_print_track(track_resp);
			/* printf("           0 votes-offs.\n"); */
			hgd_hline();
		} else
			hgd_print_track(track_resp);

		free(track_resp);
	}

	return (0);
}

/*
 * Heads up display mode
 * May make this more spctacular at some stage...
 */
int
hgd_req_hud(char **args)
{
	args = args; /* silence */

	system("clear");
	while (1) {
		printf("HGD Server @ %s -- Playlist:\n\n", host);
		hgd_req_playlist(NULL);
		sleep(1);
		system("clear");
	}

	return 0;
}

/* lookup for request despatch */
struct hgd_req_despatch req_desps[] = {
	{"ls",		0,	hgd_req_playlist},
	{"hud",		0,	hgd_req_hud},
	/*"np",		0,	hgd_req_now_playing}, */
	{"vo",		0,	hgd_req_vote_off},
	{"q",		1,	hgd_req_queue},
	{NULL,		0,	NULL} /* terminate */
};

/* parse command line args */
void
hgd_exec_req(int argc, char **argv)
{
	struct hgd_req_despatch	*desp, *correct_desp = NULL;

	if (argc == 0) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
	}

	for (desp = req_desps; desp->req != NULL; desp++) {
		if (strcmp(desp->req, argv[0]) != 0)
			continue;
		if (argc - 1 != desp->n_args)
			continue;

		correct_desp = desp; /* found it */
		break;
	}

	if (correct_desp == NULL) {
		hgd_usage();
		exit_ok = 1;
		hgd_exit_nicely();
	}

	/* once we know that the hgdc is used properly, open connection */
	hgd_setup_socket();
	DPRINTF(HGD_D_DEBUG, "Despatching request '%s'", correct_desp->req);
	correct_desp->handler(&argv[1]);
}

int
ssl_connect(int fd)
{
	OpenSSL_add_all_algorithms();   /* load & register cryptos */
	SSL_load_error_strings();     /* load all error messages */
	method = SSLv2_client_method();   /* create client instance */
	ctx = SSL_CTX_new(method);         /* create context */

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_connect(ssl);

	return 0;
}

int
main(int argc, char **argv)
{
	char			*resp, ch;

	while ((ch = getopt(argc, argv, "hp:s:vx:e")) != -1) {
		switch (ch) {
		case 'e':
			DPRINTF(HGD_D_DEBUG, "Enabled encryption");
			will_encrypt = 1;
			break;
		case 's':
			DPRINTF(HGD_D_DEBUG, "Set server to %s", optarg);
			host = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "set port to %d", port);
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
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

	/* do whatever the user wants */
	hgd_exec_req(argc, argv);

	/* sign off */
	hgd_sock_send_line(sock_fd, ssl, "bye");
	resp = hgd_sock_recv_line(sock_fd, ssl);
	hgd_check_svr_response(resp, 1);
	free(resp);

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
