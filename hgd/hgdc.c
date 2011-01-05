#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "hgd.h"

int
main(int argc, char **argv)
{
	argc = argc; argv = argv;

	exit (EXIT_SUCCESS);
}
