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

#ifndef __PY_H
#define __PY_H

#include "hgd.h"

#define PRINT_PY_ERROR()	do { \
					PyErr_Print(); \
					DPRINTF(HGD_D_ERROR, "Python error"); \
				} while (0);

/* python extensions */
#define HGD_MAX_PY_MODS		32
#define HGD_DFL_PY_PLUGIN_DIR	HGD_DFL_SVR_CONF_DIR "/plugins"

extern char			*hgd_py_plugin_dir;

/* this describes the hgd object in python */
typedef struct {
	PyObject_HEAD
	int			 proto_version;
	PyObject		*hgd_version;
	int			 debug_level;
	PyObject		*component;	/* "hgd-playd", "hgd-netd"... */
} Hgd;

/* module table - these are user moduels which we load and call hooks on */
struct hgd_py_modules {
	/* native modules */
	PyObject		*hgd_o;			/* ptr to hgd object */
	/* our non-native modules */
	PyObject		*playlist_mod;		/* playlist.py */
	/* stock modules */
	PyObject		*inspect_mod;		/* for hgd.dprint() */
	/* user hook modules loaded from script dir */
	PyObject		*user_mods[HGD_MAX_PY_MODS];
	char			*user_mod_names[HGD_MAX_PY_MODS];
	uint8_t			 n_user_mods;
};
extern struct hgd_py_mods	 hgd_pys;

int				 hgd_embed_py(uint8_t enable_user_scripts);
void				 hgd_free_py(void);
int				 hgd_execute_py_hook(char *hook);

#endif
