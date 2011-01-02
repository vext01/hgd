#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "hgd.h"

#define HGD_DFL_PORT		6633
#define HGD_DFL_BACKLOG		5

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
int				svr_fd = -1;
uint8_t				hgd_debug = 1;

/* die nicely, closing socket */
void
hgd_kill_sighandler(int sig)
{
	sig = sig;

	if (svr_fd >= 0)
		close(svr_fd);

	exit (EXIT_SUCCESS);

}

/* when a client is accepted, we go here */
void
hgd_service_client(int cli_fd, struct sockaddr_in *cli_addr)
{
	char			*cli_str;
	struct hostent		*cli_host;

	cli_fd = cli_fd; /* for now silence compiler */

	DPRINTF("%s: servicing client\n", __func__);

	cli_host = gethostbyaddr(&(cli_addr->sin_addr),
	    sizeof((cli_addr->sin_addr)), AF_INET);

	if (cli_host) {
		DPRINTF("%s: client hostname found\n", __func__);
		cli_str = cli_host->h_name;
	} else {
		DPRINTF("%s: client hostname *not* found\n", __func__);
		cli_str = xmalloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(cli_addr->sin_addr),
		    cli_str, INET_ADDRSTRLEN);
	}

	DPRINTF("%s: accepted connection from client '%s'\n",
	    __func__, cli_str);
}

/* main loop that deals with network requests */
void
hgd_listen_loop()
{
	struct sockaddr_in	addr, cli_addr;
	int			cli_fd, child_pid;
	socklen_t		cli_addr_len;

	DPRINTF("%s: setting up socket\n", __func__);

	/* if killed, die nicely */
	signal(SIGKILL, hgd_kill_sighandler);

	if ((svr_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		errx(EXIT_FAILURE, "%s: socket(): ", __func__);

	/* configure socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(svr_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		errx(EXIT_FAILURE,
		    "%s: can't bind to port %d", __func__, port);
	}

	listen(svr_fd, sock_backlog);

	DPRINTF("%s: socket ready and listening on port %d\n", __func__, port);

	while (1) {

		DPRINTF("%s: waiting for client connection\n", __func__);

		cli_addr_len = sizeof(cli_addr_len);
		cli_fd = accept(svr_fd, (struct sockaddr *) &cli_addr,
		    &cli_addr_len);

		if (cli_fd < 0) {
			warn("%s: server failed to accept", __func__);
			continue;
		}

		/* ok, let's deal with that request then */
		child_pid = fork();

		if (!child_pid) {
			hgd_service_client(cli_fd, &cli_addr);
			DPRINTF("%s: client disconnected\n", __func__);
			close(svr_fd);
			close(cli_fd);
			exit (EXIT_SUCCESS); /* client is done */
		}
		DPRINTF("%s: client servicer PID = '%d'\n",
		    __func__, child_pid);
		/* otherwise, back round for the next client */
	}

	/* NOREACH ATM */
	close(svr_fd);
}

int
main(int argc, char **argv)
{
	argc = argc; argv = argv;

	/* getopt XXX */
	if (argc > 1)
		port = atoi(argv[1]);

	hgd_listen_loop();
	return (EXIT_SUCCESS);
}
