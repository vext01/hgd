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

#include <shout/shout.h>

#include "config.h"
#include "hgd.h"
#include "shout.h"

/* XXX config options */
#define HGD_SHOUT_HOST		"192.168.1.81"
#define HGD_SHOUT_USER		"source"
#define HGD_SHOUT_PASS		"secret"
#define HGD_SHOUT_PORT		8000
#define HGD_SHOUT_MOUNT		"/hgd.ogg"

shout_t				*shout = NULL;

int
hgd_init_shout()
{
	DPRINTF(HGD_D_INFO, "Initialising shout: http://%s:%d%s",
	    HGD_SHOUT_HOST, HGD_SHOUT_PORT, HGD_SHOUT_MOUNT);

	shout_init();

	shout = shout_new();
	if (!shout) {
		DPRINTF(HGD_D_ERROR, "Could not init shout: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_host(shout, HGD_SHOUT_HOST) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout host: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_protocol(shout, SHOUT_PROTOCOL_HTTP) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout proto: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_port(shout, HGD_SHOUT_PORT) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout port: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_password(shout, HGD_SHOUT_PASS) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout pass: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}
	if (shout_set_mount(shout, HGD_SHOUT_MOUNT) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout mount: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_user(shout, HGD_SHOUT_USER) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout user: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_set_format(shout, SHOUT_FORMAT_OGG) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not set shout format: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	if (shout_open(shout) != SHOUTERR_SUCCESS) {
		DPRINTF(HGD_D_ERROR, "Could not open shout connection: %s",
		    shout_get_error(shout));
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_INFO, "Shout initialised");
	return (HGD_OK);
}

int
hgd_close_shout()
{
	if (shout)
		shout_close(shout);

	shout_shutdown();

	return (HGD_OK);
}
