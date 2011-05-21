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

struct hgd_py_modules		hgd_py_mods;

/*
 * XXX - reference counts, all over the place!
 */

/*
 * methods exposed to python
 */

/*
 * Testing a method call
 * args :
 * returns : None
 */
static PyObject *
hgd_py_meth_test(Hgd *self)
{
	self = self; /* sssh */
	printf("Ya, hi, i work\n");
	Py_RETURN_NONE;
}

/* method table */
static PyMethodDef hgd_methods[] = {
	{"test",
	    (PyCFunction) hgd_py_meth_test, METH_NOARGS, "test the damned thing"},
	{ 0, 0, 0, 0 }
};

/*
 * Describe the hgd object type
 * This is for Python 2.6 and will probably make warnings on other versions
 */
static PyTypeObject HgdType = {
	PyObject_HEAD_INIT(NULL)
	0,				/* ob_size */
	"hgd.Hgd",			/* tp_name */
	sizeof(Hgd),			/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	"Hackathon Gunther Daemon",	/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	hgd_methods,			/* tp_methods */
	0,				/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	0,				/* tp_new */
	0,				/* tp_free */
	0,				/* tp_is_gc */
	0,				/* tp_bases */
	0,				/* tp_mro */
	0,				/* tp_cache */
	0,				/* tp_subclasses */
	0,				/* tp_weaklis */
	0,				/* destructor */
	0,				/* tp_version_tag */
#ifdef COUNT_ALLOCS
	0,				/* tp_allocs */
	0,				/* tp_frees */
	0,				/* tp_maxalloc */
	0,				/* tp_prev */
	0,				/* tp_next */
#endif
};

/*
 * initialise hgd module
 */
#ifndef PyMODINIT_FUN
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
inithgd(void)
{
    PyObject* m;

    HgdType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&HgdType) < 0)
        return;

    m = Py_InitModule3("hgd", hgd_methods,
                       "Hackathon Gunther Daemon Extensions");

    Py_INCREF(&HgdType);
    PyModule_AddObject(m, "Hgd", (PyObject *) &HgdType);
}

/*
 * Back to HGD land
 */

/* embed the Python interpreter */
int
hgd_embed_py()
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

	memset(&hgd_py_mods, 0, sizeof(hgd_py_mods));

	script_dir = opendir(HGD_DFL_PY_DIR);
	if (script_dir == NULL) {
		DPRINTF(HGD_D_ERROR, "Can't read script dir '%s': %s",
		    HGD_DFL_PY_DIR, SERROR);
		hgd_exit_nicely();
	}

	/* loop over script dir loading modules */
	while ((ent = readdir(script_dir)) != NULL) {

		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0)) {
			continue;
		}

		if (hgd_py_mods.n_mods == HGD_MAX_PY_MODS) {
			DPRINTF(HGD_D_WARN, "too many python modules loaded");
			break;
		}

		ent->d_name[strlen(ent->d_name) - 3] = 0;
		DPRINTF(HGD_D_DEBUG, "Loading '%s'", ent->d_name);
		mod = PyImport_ImportModule(ent->d_name);

		if (!mod) {
			PRINT_PY_ERROR();
			continue;
		}

		hgd_py_mods.mods[hgd_py_mods.n_mods] = mod;
		hgd_py_mods.mod_names[hgd_py_mods.n_mods] = xstrdup(ent->d_name);
		hgd_py_mods.n_mods++;

	}

	(void) closedir(script_dir);

	inithgd();
	hgd_py_mods.hgd_o = _PyObject_New(&HgdType);

	return (HGD_OK);
}

void
hgd_free_py()
{
	DPRINTF(HGD_D_INFO, "Clearing up python stuff");

	Py_Finalize();
	while (hgd_py_mods.n_mods)
		free(hgd_py_mods.mod_names[--hgd_py_mods.n_mods]);

}

int
hgd_execute_py_hook(char *hook)
{
	PyObject		*func, *ret, *args;
	int			 i, c_ret, any_errors = HGD_OK;
	char			*func_name = NULL;

	DPRINTF(HGD_D_INFO, "Executing Python hooks for '%s'", hook);

	xasprintf(&func_name, "hgd_hook_%s", hook);

	for (i = 0; i < hgd_py_mods.n_mods; i++) {
		func = PyObject_GetAttrString(hgd_py_mods.mods[i], func_name);

		/* if a hook func is not defined, that is fine, skip */
		if (!func) {
			DPRINTF(HGD_D_INFO, "Python hook '%s.%s' undefined",
			    hgd_py_mods.mod_names[i], func_name);
			continue;
		}

		if (!PyCallable_Check(func)) {
			PRINT_PY_ERROR();
			DPRINTF(HGD_D_WARN,
			    "Python hook '%s.%s' is not callable",
			    hgd_py_mods.mod_names[i], func_name);
			continue;
		}

		args = PyTuple_New(1);
		PyTuple_SetItem(args, 0, hgd_py_mods.hgd_o);

		DPRINTF(HGD_D_INFO, "Calling Python hook '%s.%s'",
		    hgd_py_mods.mod_names[i], func_name);

		ret = PyObject_CallObject(func, args);
		if (ret == NULL) {
			PRINT_PY_ERROR();
			DPRINTF(HGD_D_WARN,
			    "failed to call Python hook '%s.%s'",
			    hgd_py_mods.mod_names[i], func_name);
			continue;
		}

		c_ret = PyInt_AsLong(ret);

		/* if the user returns non HGD_OK (non-zero), indicates fail */
		if (c_ret != HGD_OK) {
			DPRINTF(HGD_D_WARN, "%s.%s returned non-zero",
			    hgd_py_mods.mod_names[i], func_name);
			any_errors = HGD_FAIL;
		}
	}

	free(func_name);

	return (any_errors);
}

#endif
