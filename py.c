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
#include <structmember.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>

#include "hgd.h"
#include "py.h"
#include "db.h"

struct hgd_py_modules		 hgd_py_mods;
char				*hgd_py_plugin_dir;

/*
 * methods exposed to python
 */

/*
 * debug message
 *
 * args: level, message
 * ret:
 */
static PyObject *
hgd_py_func_dprint(PyObject *self, PyObject *args)
{
	PyObject		*f_currentframe = NULL, *f_getframeinfo = NULL;
	PyObject		*currentframe = NULL, *frameinfo = NULL;
	PyObject		*a_getframeinfo = NULL, *arg1 = NULL;
	PyObject		*file = NULL, *line = NULL, *str_arg1 = NULL;
	PyObject		*meth = NULL;
	long			 level;
	int			 err = 0;

	(void)self;

	if (PyArg_ParseTuple(args, "lO", &level, &arg1) == 0) {
		err = 1;
		goto clean;
	}

	/* silent if debug level not high enough */
	if (level > hgd_debug)
		goto clean;

	/* get current frame */
	f_currentframe = PyObject_GetAttrString(
	    hgd_py_mods.inspect_mod, "currentframe");
	if (!f_currentframe) {
		err = 1;
		goto clean;
	}

	DPRINTF(HGD_D_INFO, "Calling currentframe()");
	currentframe = PyObject_CallObject(f_currentframe, NULL);
	if (currentframe == NULL) {
		err = 1;
		goto clean;
	}

	/* get frame info */
	f_getframeinfo = PyObject_GetAttrString(
	    hgd_py_mods.inspect_mod, "getframeinfo");
	if (!f_getframeinfo) {
		err = 1;
		goto clean;
	}

	a_getframeinfo = Py_BuildValue("(O)", currentframe);
	if (a_getframeinfo == NULL) {
		err = 1;
		goto clean;
	}

	DPRINTF(HGD_D_INFO, "Calling getframeinfo()");
	frameinfo = PyObject_CallObject(f_getframeinfo, a_getframeinfo);
	if (frameinfo == NULL) {
		err = 1;
		goto clean;
	}

	/* don't decref these, borrowed from frameinfo */
	file = PyTuple_GetItem(frameinfo, 0);
	line = PyTuple_GetItem(frameinfo, 1);
	meth = PyTuple_GetItem(frameinfo, 2);

	/* Convert the message to a string */
	arg1 = PyTuple_GetItem(args, 1);
	str_arg1 = PyObject_Str(arg1);
	if (!str_arg1) {
		err = 1;
		goto clean;
	}

	fprintf(stderr, "[Python: %s - %08d %s:%s():%ld]\n\t%s\n",
	    debug_names[level],
	    getpid(),
	    PyString_AsString(file),
	    PyString_AsString(meth),
	    PyLong_AsLong(line),
	    PyString_AsString(str_arg1));

clean:
	Py_XDECREF(f_currentframe);
	Py_XDECREF(frameinfo);
	Py_XDECREF(currentframe);
	Py_XDECREF(f_getframeinfo);
	Py_XDECREF(a_getframeinfo);
	Py_XDECREF(str_arg1);

	if (!err)
		Py_RETURN_NONE;
	return (NULL);
}

/*
 * get the contents of the playlist
 *
 * XXX needs to lock database when we make
 * the playlist re-orderable.
 *
 * args:
 * ret: list of hgd.playlist.PlaylistItem
 */
static PyObject *
hgd_py_meth_Hgd_get_playlist(Hgd *self)
{
	struct hgd_playlist	  list;
	struct hgd_playlist_item *it;
	unsigned int		  i, err = 0, free_playlist = 0;
	PyObject		 *rec = NULL, *ret_list = NULL;
	PyObject		 *plist_item = NULL;
	PyObject		 *ctor = NULL, *args = NULL;

	self = self;

	if (hgd_get_playlist(&list) == HGD_FAIL) {
		(void) PyErr_Format(PyExc_RuntimeError,
		    "Failed to get playlist from HGD");
		err = 1;
		goto clean;
	}
	free_playlist = 1;

	ret_list = PyList_New(list.n_items);
	if (!ret_list) {
		err = 1;
		goto clean;
	}

	/* get ready to construct some stuff */
	ctor = PyObject_GetAttrString(hgd_py_mods.playlist_mod, "PlaylistItem");
	if (!ctor) {
		err = 1;
		goto clean;
	}

	if (!PyCallable_Check(ctor)) {
		err = 1;
		goto clean;
	}

	for (i = 0; i < list.n_items; i++) {
		it = list.items[i];

		rec = Py_BuildValue("{sissssssss}",
		    "tid", it->id,
		    "filename", it->filename,
		    "tag_artist", it->tag_artist,
		    "tag_title", it->tag_title,
		    "user", it->user);

		if (rec == NULL) {
			err = 1;
			goto clean;
		}

		args = Py_BuildValue("(O)", rec);
		if (args == NULL) {
			err = 1;
			goto clean;
		}

		plist_item = PyObject_CallObject(ctor, args);
		Py_XDECREF(args);
		Py_XDECREF(rec);
		if (plist_item == NULL) {
			err = 1;
			goto clean;
		}

		/* steals ref */
		if (PyList_SetItem(ret_list, i, plist_item) != 0) {
			err = 1;
			goto clean;
		}
	}

clean:
	Py_XDECREF(ctor);
	if (free_playlist)
		hgd_free_playlist(&list);

	if (err)
		return (NULL);
	return (ret_list);
}

/* make some stuff read only */
static int
hgd_py_meth_Hgd_read_only_raise(Hgd self, PyObject *value, void *closure)
{
	(void)closure;
	(void)value;
	(void)self;
	(void) PyErr_Format(PyExc_AttributeError, "attribute is read-only");
	return (-1);
}

static PyObject *
hgd_py_meth_Hgd_get_hgd_version(Hgd *self, void *closure)
{
	(void)closure;
	Py_INCREF(self->hgd_version);
	return (self->hgd_version);
}

static PyObject *
hgd_py_meth_Hgd_get_proto_version(Hgd *self, void *closure)
{
	(void)closure;
	return (PyInt_FromLong(self->proto_version));
}

static PyObject *
hgd_py_meth_Hgd_get_debug_level(Hgd *self, void *closure)
{
	(void)closure;
	return (PyInt_FromLong(self->debug_level));
}

static PyObject *
hgd_py_meth_Hgd_get_component(Hgd *self, void *closure)
{
	(void)closure;
	Py_INCREF(self->component);
	return (self->component);
}

/* method table for the Hgd type */
static PyMethodDef hgd_py_Hgd_methods[] = {
	{"get_playlist",
	    (PyCFunction) hgd_py_meth_Hgd_get_playlist,
	    METH_NOARGS,
	    "Get the current hgd playlist. "
	    "Returns a List of hgd.playlist.PlaylistItem"},
	{ 0, 0, 0, 0 }
};

/* member table for Hgd type */
static PyMemberDef hgd_py_Hgd_members[] = {
	/* empty, as all members need to be read only for now */
	{0, 0, 0, 0, 0}
};

/* member get/set table for Hgd type */
static PyGetSetDef hgd_py_Hgd_get_setters[] = {
	{"hgd_version", (getter) hgd_py_meth_Hgd_get_hgd_version,
		(setter) hgd_py_meth_Hgd_read_only_raise,
		"hgd version", NULL},
	{"proto_version", (getter) hgd_py_meth_Hgd_get_proto_version,
		(setter) hgd_py_meth_Hgd_read_only_raise,
		"hgd protocol version", NULL},
	{"debug_level", (getter) hgd_py_meth_Hgd_get_debug_level,
		(setter) hgd_py_meth_Hgd_read_only_raise,
		"hgd debug level", NULL},
	{"component", (getter) hgd_py_meth_Hgd_get_component,
		(setter) hgd_py_meth_Hgd_read_only_raise,
		"hgd component", NULL},
	{NULL, NULL, NULL, NULL, NULL}  /* Sentinel */
};

/* __new__ */
static PyObject *
hgd_py_meth_Hgd_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	Hgd			*self;

	DPRINTF(HGD_D_DEBUG, "__new__ hgd object");

	/* quiet */
	args = args;
	kwds = kwds;

	self = (Hgd *)type->tp_alloc(type, 0);

	if (self != NULL) {
		self->hgd_version = PyString_FromString(HGD_VERSION);
		if (self->hgd_version == NULL) {
			DPRINTF(HGD_D_ERROR, "couldn't init self.hgd_version");
			Py_DECREF(self);
			return NULL;
		}

		self->component = PyString_FromString(hgd_component);
		if (self->component == NULL) {
			DPRINTF(HGD_D_ERROR, "couldn't init self.componentn");
			Py_DECREF(self);
			return NULL;
		}
	}

	self->proto_version = HGD_PROTO_VERSION_MAJOR;
	/* XXX 0.5.0 minor version */
	self->debug_level = hgd_debug;

	return (PyObject *)self;
}

/* __init__ */
static int
hgd_py_meth_Hgd_init(Hgd *self, PyObject *args, PyObject *kwds)
{
	DPRINTF(HGD_D_INFO, "__init__ hgd object");

	/* quiet */
	(void)self;
	(void)args;
	(void)kwds;

	self->proto_version = 0;
	self->debug_level = 0;
	self->component = Py_None;
	self->hgd_version = Py_None;

	return (0);
}

static void
hgd_py_meth_Hgd_dealloc(Hgd *self)
{
	if (self != NULL) {
		if (self->hgd_version != NULL) {
			Py_XDECREF(self->hgd_version);
		}

		if (self->component != NULL) {
			Py_XDECREF(self->component);
		}
		self->ob_type->tp_free((PyObject*)self);
	}
}


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
	(destructor) hgd_py_meth_Hgd_dealloc,	/* tp_dealloc */
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	"Core HGD glue. An instance of this is passed to each hook.",
					/* ^^^ tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	hgd_py_Hgd_methods,		/* tp_methods */
	hgd_py_Hgd_members,		/* tp_members */
	hgd_py_Hgd_get_setters,		/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc) hgd_py_meth_Hgd_init,	/* tp_init */
	0,				/* tp_alloc */
	hgd_py_meth_Hgd_new,		/* tp_new */
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

/* attribute table for the hgd module */
static PyMethodDef hgd_py_hgd_mod_attrs[] = {
	{"dprint",
	    (PyCFunction) hgd_py_func_dprint,
	    METH_VARARGS, "Print a debug message\n\nKeyword arguments\n"
	    "debug_level -- debug level to show message at.\n"
	    "               This should be one of: hgd.D_ERROR, hgd.D_WARN, "
	    "hgd.D_INFO, hgd.D_DEBUG\n"
	    "msg         -- The message to show."
	},
	{ 0, 0, 0, 0 }
};

/*
 * initialise hgd module
 */
#ifndef PyMODINIT_FUN
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
hgd_init_hgd_mod(void)
{
	PyObject			*m = NULL, *dict = NULL;

	HgdType.tp_new = PyType_GenericNew;
	if (PyType_Ready(&HgdType) < 0) {
		DPRINTF(HGD_D_ERROR, "Hgd type not ready");
		return;
	}

	m = Py_InitModule3("hgd", hgd_py_hgd_mod_attrs,
	    "Hackathon Gunther Daemon Extensions");

	dict = PyModule_GetDict(m); /* never fails (tm) */

	/* add debug levels to global namespace of module */
	PyDict_SetItemString(dict, "D_ERROR", PyLong_FromLong(HGD_D_ERROR));
	PyDict_SetItemString(dict, "D_WARN", PyLong_FromLong(HGD_D_WARN));
	PyDict_SetItemString(dict, "D_INFO", PyLong_FromLong(HGD_D_INFO));
	PyDict_SetItemString(dict, "D_DEBUG", PyLong_FromLong(HGD_D_DEBUG));
	PyDict_SetItemString(dict, "__author__",
	    PyString_FromString("Edd Barrett"));

	Py_INCREF(&HgdType);
	PyModule_AddObject(m, "Hgd", (PyObject *) &HgdType);
}

/*
 * Back to HGD land
 */

/* embed the Python interpreter */
int
hgd_embed_py(uint8_t enable_user_scripts)
{
	DIR			*script_dir;
	struct dirent		*ent;
	PyObject		*mod;
	char			*search_path;
	size_t			 s_nm_len;

	DPRINTF(HGD_D_INFO, "Initialising Python");

	if (hgd_py_plugin_dir == NULL) {
		hgd_py_plugin_dir = xstrdup(HGD_DFL_PY_PLUGIN_DIR);
	}

	/* ensure we find our modules */
	xasprintf(&search_path, "%s:%s:%s",
	    DATAROOTDIR "/hgd/pylib", BUILD_DIR "/pylib",
	    hgd_py_plugin_dir);
	DPRINTF(HGD_D_DEBUG, "Python search path is '%s'", search_path);

	if (setenv("PYTHONPATH", search_path, 0) == -1) {
		DPRINTF(HGD_D_ERROR,
		    "Can't set python search path: %s", SERROR);
		free(search_path);
		hgd_exit_nicely();
	}
	free(search_path);

	Py_Initialize();
	memset(&hgd_py_mods, 0, sizeof(hgd_py_mods));

	/* import inspect for hgd.dprint */
	mod = PyImport_ImportModule("inspect");
	if (!mod) {
		PRINT_PY_ERROR();
		hgd_exit_nicely();
	}
	hgd_py_mods.inspect_mod = mod;

	/* always import the hgd support stuff from hgd.py */
	mod = PyImport_ImportModule("hgd.playlist");
	if (!mod) {
		PRINT_PY_ERROR();
		hgd_exit_nicely();
	}
	hgd_py_mods.playlist_mod = mod;

	/* if we want to enable user scripts */
	if (enable_user_scripts) {

		script_dir = opendir(hgd_py_plugin_dir);
		if (script_dir == NULL) {
			DPRINTF(HGD_D_WARN, "Can't read script dir '%s': %s",
			   hgd_py_plugin_dir, SERROR);
		}

		/* loop over user script dir loading modules for hooks */
		while ((script_dir != NULL)
		    && (ent = readdir(script_dir)) != NULL) {

			if ((strcmp(ent->d_name, ".") == 0) ||
			    (strcmp(ent->d_name, "..") == 0) ||
			    (strcmp(ent->d_name, "hgd.py") == 0)) {
				continue;
			}

			if (hgd_py_mods.n_user_mods == HGD_MAX_PY_MODS) {
				DPRINTF(HGD_D_WARN,
				    "Too many python modules loaded");
				break;
			}

			s_nm_len = strlen(ent->d_name);
			if (s_nm_len < 4) {
				DPRINTF(HGD_D_INFO,
				    "skipping '%s', filename too short",
				    ent->d_name);
				continue;
			}

			/* scripts must end '.py' */
			if ((ent->d_name[s_nm_len - 1] != 'y') ||
			    (ent->d_name[s_nm_len - 2] != 'p') ||
			    (ent->d_name[s_nm_len - 3] != '.')) {
				DPRINTF(HGD_D_INFO,
				    "skipping '%s', not a '.py' suffix",
				    ent->d_name);
				continue;
			}

			/* remove .py  suffix */
			ent->d_name[s_nm_len - 3] = 0;

			/* load */
			DPRINTF(HGD_D_DEBUG, "Loading '%s'", ent->d_name);
			mod = PyImport_ImportModule(ent->d_name);
			if (!mod) {
				PRINT_PY_ERROR();
				continue;
			}

			hgd_py_mods.user_mods[hgd_py_mods.n_user_mods] = mod;
			hgd_py_mods.user_mod_names[hgd_py_mods.n_user_mods] =
			    xstrdup(ent->d_name);
			hgd_py_mods.n_user_mods++;
		}
		DPRINTF(HGD_D_INFO,
		    "Loaded %d user scripts.", hgd_py_mods.n_user_mods);

	if (script_dir != NULL)	(void) closedir(script_dir);

	} /* if enable_user_scripts */

	/* init hgd module and stash an instance */
	hgd_init_hgd_mod();
	hgd_py_mods.hgd_o = hgd_py_meth_Hgd_new(&HgdType, NULL, NULL);

	hgd_execute_py_hook("init");

	return (HGD_OK);
}

void
hgd_free_py()
{
	DPRINTF(HGD_D_INFO, "Clearing up python stuff");
	hgd_py_meth_Hgd_dealloc((Hgd *) hgd_py_mods.hgd_o);

	if (hgd_py_plugin_dir != NULL)
		free(hgd_py_plugin_dir);

	Py_Finalize();
	while (hgd_py_mods.n_user_mods)
		free(hgd_py_mods.user_mod_names[--hgd_py_mods.n_user_mods]);

}

int
hgd_execute_py_hook(char *hook)
{
	PyObject		*func, *ret, *args;
	int			 i, c_ret, any_errors = HGD_OK;
	char			*func_name = NULL;

	DPRINTF(HGD_D_DEBUG, "Executing Python hooks for '%s'", hook);

	xasprintf(&func_name, "hgd_hook_%s", hook);

	for (i = 0; i < hgd_py_mods.n_user_mods; i++) {
		func = PyObject_GetAttrString(
		    hgd_py_mods.user_mods[i], func_name);

		/* if a hook func is not defined, that is fine, skip */
		if (!func) {
			DPRINTF(HGD_D_DEBUG, "Python hook '%s.%s' undefined",
			    hgd_py_mods.user_mod_names[i], func_name);
			PyErr_Clear();
			continue;
		}

		if (!PyCallable_Check(func)) {
			PRINT_PY_ERROR();
			DPRINTF(HGD_D_WARN,
			    "Python hook '%s.%s' is not callable",
			    hgd_py_mods.user_mod_names[i], func_name);
			Py_XDECREF(func);
			any_errors = HGD_FAIL;
			continue;
		}

		args = Py_BuildValue("(O)", hgd_py_mods.hgd_o);
		if (args == NULL) {
			DPRINTF(HGD_D_WARN,
			    "Failed to build args for '%s.%s'",
			    hgd_py_mods.user_mod_names[i], func_name);
			any_errors = HGD_FAIL;
			Py_XDECREF(func);
			continue;
		}

		DPRINTF(HGD_D_INFO, "Calling Python hook '%s.%s'",
		    hgd_py_mods.user_mod_names[i], func_name);

		ret = PyObject_CallObject(func, args);
		Py_XDECREF(func);
		Py_XDECREF(args);
		if (ret == NULL) {
			PRINT_PY_ERROR();
			DPRINTF(HGD_D_WARN,
			    "failed to call Python hook '%s.%s'",
			    hgd_py_mods.user_mod_names[i], func_name);
			any_errors = HGD_FAIL;
			continue;
		}

		c_ret = PyInt_AsLong(ret);
		Py_XDECREF(ret);

		/* if the user returns non HGD_OK (non-zero), indicates fail */
		if (c_ret != HGD_OK) {
			DPRINTF(HGD_D_WARN, "%s.%s returned non-zero",
			    hgd_py_mods.user_mod_names[i], func_name);
			any_errors = HGD_FAIL;
		}
	}

	free(func_name);

	return (any_errors);
}

#endif
