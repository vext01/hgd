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

#define _GNU_SOURCE	/* linux */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <signal.h>

#include "config.h"
#include "hgd.h"
#include "mplayer.h"

char			*mplayer_fifo_path = 0;

int
hgd_init_mplayer_globals()
{
	xasprintf(&mplayer_fifo_path, "%s/%s",
	    state_path, HGD_MPLAYER_PIPE_NAME);

	return (HGD_OK);
}

int
hgd_free_mplayer_globals()
{
	if (mplayer_fifo_path)
		free(mplayer_fifo_path);
	mplayer_fifo_path = 0;

	return (HGD_OK);
}

int
hgd_mplayer_pipe_send(char *what)
{
	FILE			*pipe = NULL;
	int			 ret = HGD_FAIL;

	if ((pipe = fopen(mplayer_fifo_path, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR,
		    "Can't open mplayer pipe, is a track playing?\n");
		goto clean;
	}

	if (fwrite(what, strlen(what), 1, pipe) == 0) {
		if (ferror(pipe))
			DPRINTF(HGD_D_ERROR,
			    "Failed to write to pipe: %s", SERROR);
		goto clean;
	}

	ret = HGD_OK;
clean:
	if (pipe)
		fclose(pipe);
	if (mplayer_fifo_path)
		free(mplayer_fifo_path);

	return (ret);
}
