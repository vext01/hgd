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
#include <sys/types.h>
#include <dirent.h>

#include "hgd.h"
#include "py.h"

struct hgd_py_mods		hgd_pys;

/* embed the Python interpreter */
int
hgd_init_py()
{
	DIR			*script_dir;
	struct dirent		*ent;
	PyObject		*mod;

	DPRINTF(HGD_D_INFO, "Initialising Python");

	/* ensure we find our modules */
	if (setenv("PYTHONPATH", HGD_DFL_PY_DIR, 0) == -1) {
		DPRINTF(HGD_D_ERROR, "Can't set python search path: %s", SERROR);
		hgd_exit_nicely();
	}

	Py_Initialize();

	memset(&hgd_pys, 0, sizeof(hgd_pys));

	script_dir = opendir(HGD_DFL_PY_DIR);
	if (script_dir == NULL) {
		DPRINTF(HGD_D_ERROR, "Can't read script dir '%s': %s",
		    HGD_DFL_PY_DIR, SERROR);
		hgd_exit_nicely();
	}

	while ((ent = readdir(script_dir)) != NULL) {

		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0)) {
			continue;
		}

		ent->d_name[strlen(ent->d_name) - 3] = 0;
		DPRINTF(HGD_D_DEBUG, "Loading '%s'", ent->d_name);
		mod = PyImport_ImportModule(ent->d_name);

		if (!mod)
			PRINT_PY_ERROR();
	}

	(void) closedir(script_dir);

	return (HGD_OK);
}

void
hgd_free_py()
{
	Py_Finalize();
}

#endif
