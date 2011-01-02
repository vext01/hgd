#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hgd.h"

#define HGD_DFL_PORT		6634
#define HGD_DFL_BACKLOG		5

int				port = HGD_DFL_PORT;
int				sock_backlog = HGD_DFL_BACKLOG;
uint8_t				hgd_debug = 1;

void
hgd_listen_loop()
{
	struct sockaddr_in	addr;
	int			fd;

	DPRINTF("%s: setting up socket\n", __func__);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		errx(EXIT_FAILURE, "%s: socket(): ", __func__);

	/* configure socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		errx(EXIT_FAILURE,
		    "%s: can't bind to port %d: ", __func__, port);
	}

	listen(fd, sock_backlog);

	DPRINTF("%s: socket ready and listening\n", __func__);

	/* XXX socket loop */

	close(fd);
}

int
main(int agrc, char **argv)
{
	hgd_listen_loop();
	return (EXIT_SUCCESS);
}
