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
hgd_mk_pydoc()
{
	PyObject			*mod = NULL, *func = NULL, *args = NULL;
	PyObject			*ret = NULL;
	int				 err = HGD_OK;

	mod = PyImport_ImportModule("hgd.doccer");
	if (!mod) {
		PRINT_PY_ERROR();
		err = HGD_FAIL;
		goto clean;
	}

	func = PyObject_GetAttrString(mod, "hgd_mk_pydoc");
	if (!func) {
		PRINT_PY_ERROR();
		err = HGD_FAIL;
		goto clean;
	}

	if (!PyCallable_Check(func)) {
		PRINT_PY_ERROR();
		err = HGD_FAIL;
		goto clean;
	}

	ret = PyObject_CallObject(func, NULL);
	if (ret == NULL) {
		PRINT_PY_ERROR();
		err = HGD_FAIL;
		goto clean;
	}

clean:
	if (err != HGD_OK)
		DPRINTF(HGD_D_ERROR, "Failed to generate documentation");

	if (mod)
		Py_XDECREF(mod);
	if (func)
		Py_XDECREF(func);
	if (ret)
		Py_XDECREF(ret);

	return (err);
}

void
hgd_usage()
{
	printf("Usage: hgd-mk-pydoc [opts]\n\n");
	printf("    -h\t\t\tShow this message and exit\n");
	printf("    -x level\t\tSet debug level (0-3)\n");
}

int
main(int argc, char **argv)
{
	int			ch;

	while ((ch = getopt(argc, argv, "hx:")) != -1) {
		switch (ch) {
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
		}
	}


	hgd_register_sig_handlers();
	/* embed python, but dont load user scripts */
	if (hgd_embed_py(0) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise Python");
		hgd_exit_nicely();
	}

	hgd_mk_pydoc();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}
#else

#include <stdio.h>
#include <stdlib.h>

/* unused, but must be defined */
void
hgd_exit_nicely()
{
	exit (EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	printf("HGD was built without Python support\n");
	return (EXIT_SUCCESS);
}
#endif
