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

#include "config.h"

#ifdef HAVE_PYTHON

#include <Python.h> /* defines _GNU_SOURCE */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "py.h"

#include "hgd.h"

const char			*hgd_component = "hgd-mk-pydoc";

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-playd was interrupted or crashed\n");

	hgd_free_py();
	exit (!exit_ok);
}

int
main(int argc, char **argv)
{
	hgd_register_sig_handlers();
	/* embed python, but dont load user scripts */
	if (hgd_embed_py(0) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise Python");
		hgd_exit_nicely();
	}

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
#else

#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	printf("HGD was built without Python support\n");
	return (EXIT_SUCCESS);
}
#endif
