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

#ifndef __NCHGDC_H
#define __NCHGDC_H

#define HGD_MAX_CONTENT_WINS		3

struct ui {
	WINDOW		*title;		/* title bar */
	/*
	 * main pane in the middle.
	 * This is just a pointer to the playlist/files/console win.
	 */
	WINDOW		*status;	/* status bar */
	MENU		*menu;
	/* possible "active" windows */
	WINDOW			*content_wins[HGD_MAX_CONTENT_WINS];
	int			 active_content_win;
#define	HGD_WIN_PLAYLIST		0
#define HGD_WIN_FILES			1
#define HGD_WIN_CONSOLE			2
	int		 refresh_content;
};

void			hgd_update_titlebar(struct ui *u);

#endif /* __NCHGDC_H */
