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

#ifndef __MPLAYER_H
#define __MPLAYER_H

#include "hgd.h"

extern char		*mplayer_fifo_path;

#define HGD_MPLAYER_PIPE_NAME	"mplayer.pipe"
#define HGD_MPLAYER_PID_NAME	"mplayer.pid"

int			 hgd_init_mplayer_globals(void);
int			 hgd_free_mplayer_globals(void);
int			 hgd_mplayer_pipe_send(char *what);
int			 hgd_make_mplayer_input_fifo();
int			 hgd_play_track(
			     struct hgd_playlist_item *t, uint8_t, uint8_t);

#endif
