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

char			*user, *host = "127.0.0.1";
int			 port = HGD_DFL_PORT;
int			 sock_fd = -1;

void
hgd_exit_nicely()
{
	if (!exit_ok)
		fprintf(stderr,
		    "%s: hgdc was interrupted or crashed - cleaning up\n"
		    , __func__);

	if (sock_fd > 0) {
		if (shutdown(sock_fd, SHUT_RDWR) == -1)
			fprintf(stderr,
			    "%s: couldn't shutdown socket\n", __func__);
		close(sock_fd);
	}
	_exit(!exit_ok);
}

int
hgd_check_svr_response(char *resp, uint8_t x)
{
	int			len, err = 0;
	char			*trunc = NULL;

	len = strlen(resp);

	if (hgd_debug) {
		trunc = strdup(resp);
		//trunc[len - 2] = 0; /* remove \r\n */
		DPRINTF("%s: check reponse '%s'\n", __func__, trunc);
		free(trunc);
	} else
		trunc = trunc; /* silence compiler */

	if (len < 2) {
		fprintf(stderr, "%s: malformed server response\n", __func__);
		err = -1;
	} else if ((resp[0] != 'o') || (resp[1] != 'k')) {
		if (len < 5)
			fprintf(stderr, "%s: malformed server response\n",
			    __func__);
		else
			fprintf(stderr, "%s: failure: %s\n",
			    __func__, &resp[4]);
		err = -1;
	}

	if ((err == -1) && (x))
		hgd_exit_nicely();

	return err;
}

void
hgd_setup_socket()
{
	struct sockaddr_in	addr;
	char			*resp;
	struct hostent		*he;
	int			sockopt = 1;

	DPRINTF("%s: connecting to %s\n", __func__, host);
	he = gethostbyname("localhost");
	if (he != NULL) {
		host = inet_ntoa(*( struct in_addr*)(he->h_addr_list[0]));
		DPRINTF("%s: found ip %s\n", __func__, host);
	}

	/* set up socket address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(host);
	addr.sin_port = htons(port);

	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd < 0)
		errx(EXIT_FAILURE, "%s: can't make socket", __func__);

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR,
		    &sockopt, sizeof(sockopt)) < 0) {
		warn("%s: cannot set SO_REUSEADDR", __func__);
	}

	if (connect(sock_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sock_fd);
		errx(EXIT_FAILURE, "%s: can't connect", __func__);
	}

	/* expect a hello message */
	resp = hgd_sock_recv_line(sock_fd);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF("%s: connected to %s\n", __func__, host);
}
void
hgd_usage()
{
	fprintf(stderr, "usage: XXX\n");
}

/* upload and queue a file to the playlist */
#define HGD_BINARY_CHUNK	4096
int
hgd_req_queue(char **args)
{
	FILE			*f;
	struct stat		st;
	ssize_t			written = 0, fsize, chunk_sz;
	char			chunk[HGD_BINARY_CHUNK], *filename = args[0];
	char			*q_req, *resp;

	DPRINTF("%s: will queue '%s'\n", __func__, args[0]);

	if (stat(filename, &st) < 0) {
		warn("%s: cannot stat '%s'\n", __func__, filename);
		return -1;
	}
	fsize = st.st_size;

	/* send request to upload */
	xasprintf(&q_req, "q|%s|%d", filename, fsize);
	hgd_sock_send_line(sock_fd, q_req);
	free(q_req);

	/* check we are allowed */
	resp = hgd_sock_recv_line(sock_fd);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}
	free(resp);

	DPRINTF("%s: opening '%s' for reading\n", __func__, filename);
	f = fopen(filename, "r");
	if (f == NULL) {
		warn("%s: fopen '%s'", __func__, filename);
		return -1;
	}

	while (written != fsize) {
		if (fsize - written < HGD_BINARY_CHUNK)
			chunk_sz = fsize - written;
		else
			chunk_sz = HGD_BINARY_CHUNK;

		if (fread(chunk, chunk_sz, 1, f) != 1) {
			warn("%s: retrying fread", __func__);
			continue;
		}

		hgd_sock_send_bin(sock_fd, chunk, chunk_sz);

		written += chunk_sz;
		DPRINTF("%s: progress %d/%d bytes\n", __func__,
		   (int)  written, (int) fsize);
	}

	resp = hgd_sock_recv_line(sock_fd);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}

	DPRINTF("%s: transfer complete\n", __func__);
	free(resp);

	return (0);
}

void
hgd_print_track(char *resp)
{
	int			n_toks = 0;
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

	hgd_sock_send_line(sock_fd, "vo");

	resp = hgd_sock_recv_line(sock_fd);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return (-1);
	}

	return (0);
}

int
hgd_req_playlist(char **args)
{
	char			*resp, *track_resp, *p;
	int			n_items, i;

	args = args; /* shhh */

	hgd_sock_send_line(sock_fd, "ls");
	resp = hgd_sock_recv_line(sock_fd);
	if (hgd_check_svr_response(resp, 0) == -1) {
		free(resp);
		return -1;
	}

	for (p = resp; (*p != 0 && *p != '|'); p ++);
	if (*p != '|') {
		fprintf(stderr,
		    "%s: didn't find a argument separator", __func__);
		free(resp);
		return -1;
	}

	n_items = atoi(++p);
	free(resp);

	DPRINTF("%s: expecting %d items in playlist\n", __func__, n_items);
	for (i = 0; i < n_items; i++) {
		track_resp = hgd_sock_recv_line(sock_fd);
		if (i == 0) {
			hgd_hline();
			hgd_print_track(track_resp);
			/* printf("           0 votes-offs.\n"); */
			hgd_hline();
		} else
			hgd_print_track(track_resp);

		free(track_resp);
	}

	DPRINTF("%s: done\n", __func__);

	return (0);
}

/* lookup for request despatch */
struct hgd_req_despatch req_desps[] = {
	{"ls",		0,	hgd_req_playlist},
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

	DPRINTF("%s: despatching request '%s'\n", __func__, correct_desp->req);
	correct_desp->handler(&argv[1]);
}

int
main(int argc, char **argv)
{
	char			*user_cmd, *resp, ch;

	if (argc < 2)
		errx(EXIT_FAILURE, "%s: implement usage XXX", __func__);

	user = getenv("USER");
	if (user == NULL)
		errx(EXIT_FAILURE, "%s: can't get username", __func__);

	while ((ch = getopt(argc, argv, "hs:v")) != -1) {
		switch (ch) {
		case 's':
			DPRINTF("%s: set server to %s", __func__, optarg);
			host = optarg;
			break;
		case 'v':
			/* XXX */
			exit_ok = 1;
			hgd_exit_nicely();
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

	hgd_setup_socket();

	/* identify ourselves */
	xasprintf(&user_cmd, "user|%s", user);
	hgd_sock_send_line(sock_fd, user_cmd);

	resp = hgd_sock_recv_line(sock_fd);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF("%s: identified as %s\n", __func__, user);

	/* do whatever the user wants */
	hgd_exec_req(argc, argv);

	/* sign off */
	hgd_sock_send_line(sock_fd, "bye");
	resp = hgd_sock_recv_line(sock_fd);
	hgd_check_svr_response(resp, 1);
	free(resp);

	DPRINTF("%s: shutdown socket\n", __func__);

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
