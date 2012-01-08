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

#include <sys/types.h>

#include <stdio.h>
#include <curses.h>
#include <dirent.h>
#include <stdlib.h>
#include <menu.h>
#include <err.h>

#include "hgd.h"
#include "config.h"
#include "cfg.h"
#include "client.h"
#include "nchgdc.h"

#define	HGD_CPAIR_BARS				1
#define HGD_CPAIR_SELECTED			2
#define HGD_CPAIR_DIALOG			3
#define	HGD_CPAIR_PBAR_BG			4

#define HGD_LOG_BACKBUFFER			4096

/* status bar positioning */
#define HGD_POS_STATUS_X			0
#define HGD_POS_STATUS_Y			LINES - 1
#define HGD_POS_STATUS_W			COLS
#define HGD_POS_STATUS_H			1

/* title bar positioning */
#define HGD_POS_TITLE_X				0
#define HGD_POS_TITLE_Y				0
#define HGD_POS_TITLE_W				COLS
#define HGD_POS_TITLE_H				1

/* content windows positioning */
#define HGD_POS_CONT_X				0
#define HGD_POS_CONT_Y				1
#define HGD_POS_CONT_W				COLS
#define HGD_POS_CONT_H				LINES - 2

const char					*hgd_component = "nchgdc";

const char *window_names[] = {
	"Playlist",
	"File Browser",
	"Debug Console"
};

struct hgd_ui_log			logs;

void
hgd_exit_nicely()
{
	if (endwin() == ERR)
		DPRINTF(HGD_D_ERROR, "Failed to exit curses");

	if (!exit_ok) {
		DPRINTF(HGD_D_ERROR, "nchgdc crashed or was interrupted");
		/* XXX why not printed??? */
		printf("ERROR: nchgdc crashed or was interrupted!"
		    " Please examine the log file\n");
	}

	_exit(!exit_ok);
}

int
hgd_empty_menu(MENU *m)
{
	ITEM			**items;
	int			  n_items, i;

	items = menu_items(m);
	n_items = item_count(m);

	for (i = 0; i < n_items; i++) {
		free((char *) item_name(items[i]));
		free_item(items[i]);
	}

	return (HGD_OK);
}

int
hgd_prepare_item_string(char **ret_p, char *str)
{
	int			sz = 0, written = 0, i;
	char			*p = str, *c, *ret;

	/* We will be padding this up to UI width */
	*ret_p = xmalloc(COLS + 1);
	ret = *ret_p;

	memset(ret, ' ', COLS);
	ret[COLS] = 0;

	/* count how large the string should be */
	p = str;
	c = ret;
	while (written <= COLS) {

		if (*p == '\0')
			break; /* done */

		if (*p == '\t')
			sz = 4;
		else
			sz = 1;

		if (written + sz > COLS)
			break; /* that is all we would be able to cram in */

		if (sz == 1) { /* thus a non-tab */
			*c++ = *p;
			written++;
		} else { /* thus a tab, which expands to 4 spaces */
			for (i = 0; i < 4; i++) {
				*c = ' ';
				c++;
				written++;
			}
		}
		p++;
	}

	return (HGD_OK);
}

void
hgd_update_statusbar(struct ui *u)
{
	char			*fmt;

	wclear(u->status);
	wattron(u->status, COLOR_PAIR(HGD_CPAIR_BARS));

	xasprintf(&fmt, "%%-%ds", COLS);
	wprintw(u->status, fmt, u->status_str);
	free (fmt);
}

void
hgd_refresh_statusbar(struct ui *u)
{
	hgd_update_statusbar(u);
	wrefresh(u->status);
}

void
hgd_refresh_ui(struct ui *u)
{
	redrawwin(u->content_wins[u->active_content_win]);
	wnoutrefresh(u->content_wins[u->active_content_win]);

	hgd_update_titlebar(u);
	wnoutrefresh(u->title);

	hgd_update_statusbar(u);
	wnoutrefresh(u->status);

	doupdate();
}

int
init_log()
{
	char *logfile = NULL;

	xasprintf(&logfile, "%s/%s/nchgdc.log",
	    getenv("HOME"), HGD_USR_CFG_DIR);

	DPRINTF(HGD_D_INFO, "UI logging to '%s'", logfile);
	if ((logs.wr = fopen(logfile, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open write log: %s", SERROR);
		return (HGD_FAIL);
	}

	if ((logs.rd = fopen(logfile, "r")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open read log: %s", SERROR);
		return (HGD_FAIL);
	}

	free(logfile);

	/* Redirect stderr here, so that DPRINTF can still work */
	close(fileno(stderr));
	dup(fileno(logs.wr));

	return (HGD_OK);
}

void
hgd_update_titlebar(struct ui *u)
{
	char			*fmt = NULL, *title_str = NULL;

	DPRINTF(HGD_D_INFO, "Update titlebar window");

	wattron(u->title, COLOR_PAIR(HGD_CPAIR_BARS));

	xasprintf(&fmt, "%%-%ds", COLS);

	/* browser win shows path next to title */
	if (u->active_content_win == HGD_WIN_FILES) {
		xasprintf(&title_str, "nchgdc-%s :: %s :: %s", HGD_VERSION,
		    window_names[u->active_content_win], u->cwd);
	} else {
		xasprintf(&title_str, "nchgdc-%s :: %s", HGD_VERSION,
		    window_names[u->active_content_win]);
	}

	mvwprintw(u->title, 0, 0, fmt, title_str);

	free(title_str);
	free(fmt);
}

int
hgd_update_playlist_win(struct ui *u)
{
	ITEM			**items;
	int			  i;
	char			 *item_str;
	struct hgd_playlist	 *playlist;
	char			 *track_str;

	DPRINTF(HGD_D_INFO, "Update playlist window");

	hgd_set_statusbar_text(u, "Connected >>> Fetching playlist");
	hgd_update_statusbar(u);
	hgd_refresh_ui(u);

	if (sock_fd == -1)
		return (HGD_OK); /* not connected yet */

	/* and now populate the menu */
	if (hgd_cli_get_playlist(&playlist) != HGD_OK)
		return (HGD_FAIL);

	items = xcalloc(playlist->n_items + 1, sizeof(ITEM *));
	for (i = 0; i < playlist->n_items; i++) {

		DPRINTF(HGD_D_DEBUG, "Adding item \"%s\"",
		    playlist->items[i]->tags.title);

		if ((strcmp(playlist->items[i]->tags.artist, "")) ||
		    (strcmp(playlist->items[i]->tags.title, ""))) {

			xasprintf(&track_str, "#%03d from %-8s: '%s' by '%s'",
			    playlist->items[i]->id,
			    playlist->items[i]->user,
			    playlist->items[i]->tags.title,
			    playlist->items[i]->tags.artist);
		} else  {
			xasprintf(&track_str, "#%03d from %-8s: '%s'",
			    playlist->items[i]->id,
			    playlist->items[i]->user,
			    playlist->items[i]->filename);
		}

		hgd_prepare_item_string(&item_str, track_str);
		free(track_str);

		items[i] = new_item(item_str, NULL);
		if (items[i] == NULL)
			DPRINTF(HGD_D_WARN, "Could not make new item: %s", SERROR);
	}

	u->content_menus[HGD_WIN_PLAYLIST] = new_menu(items);
	if (u->content_menus[HGD_WIN_PLAYLIST] == NULL)
			DPRINTF(HGD_D_ERROR, "Could not make menu");

	set_menu_win(u->content_menus[HGD_WIN_PLAYLIST],
	    u->content_wins[HGD_WIN_PLAYLIST]);
	set_menu_mark(u->content_menus[HGD_WIN_PLAYLIST], "");
	set_menu_format(u->content_menus[HGD_WIN_PLAYLIST], LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_PLAYLIST],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_PLAYLIST])) != E_OK)
		DPRINTF(HGD_D_ERROR, "Could not post menu");

	hgd_set_standard_statusbar_text(u);

	return (HGD_OK);
}

int
hgd_update_files_win(struct ui *u)
{
	ITEM			**items = NULL;
	DIR			 *dir = NULL;
	int			  cur_index = 0, pass = 0;
	struct dirent		 *dirent, *dirent_copy = NULL;
	char			 *copy, *slash_append;

	wclear(u->content_wins[HGD_WIN_FILES]);

	DPRINTF(HGD_D_INFO, "Update files window");

	if ((dir = opendir(u->cwd)) == NULL) {
		DPRINTF(HGD_D_WARN, "Could not read dir: '%s'", u->cwd);
		return (HGD_FAIL);
	}

	/* make our menu items */
	items = xcalloc(sizeof(ITEM *), cur_index + 1);

	/*
	 * 2 passes over directory:
	 *   1 - directories
	 *   2 - standard files
	 */
	for (pass = 0; pass < 2; pass++) {

		rewinddir(dir);

		/* loop over directory adding items for files */
		while ((dirent = readdir(dir)) != NULL) {

			if (dirent < 0) {
				DPRINTF(HGD_D_WARN,
				    "readdir failed: %s", SERROR);
				return (HGD_FAIL);
			}

			/* skip entries not for this pass */
			if ((pass == 0) && (dirent->d_type != DT_DIR))
				continue;
			else if ((pass == 1) && (dirent->d_type == DT_DIR))
				continue;

			if (strcmp(dirent->d_name, ".") == 0)
				continue;

			/* could be more efficient */
			items = xrealloc(
			    items, sizeof(ITEM *) * (cur_index + 2));
			items[cur_index + 1] = NULL;

			/* pretty it up a bit */
			if (dirent->d_type == DT_DIR) {
				xasprintf(&slash_append, "%s/", dirent->d_name);
				hgd_prepare_item_string(&copy, slash_append);
				free(slash_append);
			} else {
				hgd_prepare_item_string(&copy, dirent->d_name);
			}

			items[cur_index] = new_item(copy, NULL);

			if (items[cur_index] == NULL) {
				DPRINTF(HGD_D_WARN,
				    "Could not make new menu item: %s", SERROR);
				free(copy);
			}

			/* jam away the dirent for later use */
			dirent_copy = xcalloc(1, sizeof(struct dirent));
			memcpy(dirent_copy, dirent, sizeof(struct dirent));
			set_item_userptr(items[cur_index], dirent_copy);

			if (items[cur_index] == NULL)
				continue;

			cur_index++;
		}
	}

	/* make the menu */
	if (u->content_menus[HGD_WIN_FILES] != NULL) {
		/* XXX clean up old menu */
	}

	u->content_menus[HGD_WIN_FILES] = new_menu(items);

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);
	set_menu_win(u->content_menus[HGD_WIN_FILES],
	    u->content_wins[HGD_WIN_FILES]);
	set_menu_mark(u->content_menus[HGD_WIN_FILES], "");
	set_menu_format(u->content_menus[HGD_WIN_FILES],
	    LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_FILES],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_FILES])) != E_OK)
		DPRINTF(HGD_D_WARN, "Could not post menu");

	return (HGD_OK);

}

int
hgd_update_console_win(struct ui *u)
{
	char		  buf[HGD_LOG_BACKBUFFER + 1], *start = buf, *end, *copy;
	long		  pos, endpos, read;
	long		  toread = HGD_LOG_BACKBUFFER;
	ITEM		**items = NULL;
	int		  cur_index = 0;

	DPRINTF(HGD_D_INFO, "Update console window");

	memset(buf, 0, HGD_LOG_BACKBUFFER + 1);

	/* find how long the log is */
	if ((fseek(logs.rd, 0, SEEK_END)) != 0)
		DPRINTF(HGD_D_WARN, "fseek: %s", SERROR);

	endpos = ftell(logs.rd);
	if (endpos < HGD_LOG_BACKBUFFER)
		toread = endpos;

	/* rewind at most HGD_LOG_BACKBUFFER and read into buffer */
	if ((fseek(logs.rd, -toread, SEEK_END)) != 0)
		DPRINTF(HGD_D_WARN, "fseek: %s", SERROR);

	pos = ftell(logs.rd);
	if ((read = fread(buf, toread, 1, logs.rd)) == 0) {
		if (ferror(logs.rd)) {
		    DPRINTF(HGD_D_WARN,
			"Failed to read console log: %s", SERROR);
		}
	}

	/* ensure we dont start printing the middle of a line */
	if (pos < 0)
		DPRINTF(HGD_D_WARN, "ftell failed: %s", SERROR);
	else if (pos != 0) {
		/* if not at the start of file, find a \n */
		while ((*start != '\n') && (*start != '\0'))
			start++;
	}

	/* this SHOULD happen, but not guaraunteed */
	if (*start == '\n')
		start++;

	items = xcalloc(sizeof(ITEM*), 1);

	/* scan for lines and add them as menu items */
	end = start;
	while (*start != 0) {
		while ((*end != 0) && (*end != '\n'))
			end++;

		if (*end == 0) {
			DPRINTF(HGD_D_WARN, "Unexpected end of log");
			break;
		}
		*end = 0;

		/* could be more efficient */
		items = xrealloc(items, sizeof(ITEM *) * (cur_index + 2));
		items[cur_index + 1] = NULL;

		hgd_prepare_item_string(&copy, start);
		items[cur_index] = new_item(copy, NULL);

		if (items[cur_index] == NULL) {
			DPRINTF(HGD_D_WARN,
			    "Could not make new menu item (%s): %s", start, SERROR);
			free(copy);
		}

		end++;
		start = end;

		if (items[cur_index] == NULL)
			continue;

		cur_index++;
	}

	/* now we have our items, make the menu */
	if (u->content_menus[HGD_WIN_CONSOLE] != NULL) {
		/* XXX clean up old menu */
	}

	u->content_menus[HGD_WIN_CONSOLE] = new_menu(items);

	keypad(u->content_wins[HGD_WIN_CONSOLE], TRUE);
	set_menu_win(u->content_menus[HGD_WIN_CONSOLE],
	    u->content_wins[HGD_WIN_CONSOLE]);
	set_menu_mark(u->content_menus[HGD_WIN_CONSOLE], "");
	set_menu_format(u->content_menus[HGD_WIN_CONSOLE],
	    LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_CONSOLE],
	    COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_CONSOLE])) != E_OK)
		DPRINTF(HGD_D_WARN, "Could not post menu");

	menu_driver(u->content_menus[HGD_WIN_CONSOLE], REQ_LAST_ITEM);

	return (HGD_OK);
}

/*
 * switches the content window and marks it for refresh
 */
int
hgd_switch_content(struct ui *u, int w)
{
	int			ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "Switch to window: %s", window_names[w]);

	if (u->content_refresh_handler[w] == NULL) {
		DPRINTF(HGD_D_WARN, "No content refresh handler defined");
		goto clean;
	}

	if (u->content_refresh_handler[w](u) != HGD_OK)
		goto clean;

	u->active_content_win = w;
	hgd_refresh_ui(u);

	ret = HGD_OK;
clean:
	return (ret);
}

int
hgd_init_titlebar(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise titlebar");

	if ((u->title = newwin(1, COLS, 0, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise titlebar");
		return (HGD_FAIL);
	}

	return (HGD_OK);
}

int
hgd_init_statusbar(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise statusbar");

	if ((u->status = newwin(HGD_POS_STATUS_H, HGD_POS_STATUS_W,
	    HGD_POS_STATUS_Y, HGD_POS_STATUS_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise statusbar");
		return (HGD_FAIL);
	}

	u->status_str = xstrdup("***");

	return (HGD_OK);
}

int
hgd_init_playlist_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise playlist window");

	/* make window */
	if ((u->content_wins[HGD_WIN_PLAYLIST] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to playlist content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_PLAYLIST], TRUE);

	/* refresh handler */
	u->content_refresh_handler[HGD_WIN_PLAYLIST] = hgd_update_playlist_win;

	return (HGD_OK);
}

/* initialise the file browser content pane */
int
hgd_init_files_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise file browser window");

	if ((u->content_wins[HGD_WIN_FILES] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);

	u->content_menus[HGD_WIN_FILES] = NULL; /* no menu */
	u->content_refresh_handler[HGD_WIN_FILES] = hgd_update_files_win;

	u->cwd = xstrdup(getenv("PWD"));

	return (HGD_OK);
}

int
hgd_init_console_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise console window");

	if ((u->content_wins[HGD_WIN_CONSOLE] = newwin(HGD_POS_CONT_H, HGD_POS_CONT_W,
	    HGD_POS_CONT_Y, HGD_POS_CONT_X)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_CONSOLE], TRUE);
	mvwprintw(u->content_wins[HGD_WIN_CONSOLE], 0, 0, "Insert console here");

	u->content_menus[HGD_WIN_CONSOLE] = NULL; /* no menu */
	u->content_refresh_handler[HGD_WIN_CONSOLE] = hgd_update_console_win;

	return (HGD_OK);
}

int
hgd_resize_app(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Resize application: %dx%d", COLS, LINES);
	
	/* update geometry of titlebar - no need to move, always (0,0)  */
	if (wresize(u->title, HGD_POS_TITLE_H, HGD_POS_TITLE_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of statusbar */
	if (mvwin(u->status, HGD_POS_STATUS_Y, HGD_POS_STATUS_X) == ERR)
		DPRINTF(HGD_D_WARN, "Could not move window: %s", SERROR);
	if (wresize(u->status, HGD_POS_STATUS_H, HGD_POS_STATUS_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of playlist window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_PLAYLIST], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of files window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_FILES], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of console window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_CONSOLE], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	return (hgd_switch_content(u, u->active_content_win));
}

/*
 * calculate dimensions of a centred, usefully sized dialog win
 */
#define				HGD_DIALOG_WIN_HRATIO		0.2
#define				HGD_DIALOG_WIN_WRATIO		0.7
int
hgd_calc_dialog_win_dims(int *y, int *x, int *h, int *w)
{
	*h = LINES * HGD_DIALOG_WIN_HRATIO;
	*w = COLS * HGD_DIALOG_WIN_WRATIO;
	*y = (LINES - *h) / 2;
	*x = (COLS - *w) / 2;

	return (HGD_OK);
}

int
hgd_centre_dialog_text(char **dest, const char *src_const)
{
	char			*next = xstrdup(src_const), *orig_copy = next;
	char			*centre_line, *tok;
	int			 centre_start;
	int			 dwidth = COLS * HGD_DIALOG_WIN_WRATIO;

	*dest = NULL;

	centre_line = malloc(dwidth + 1);

	while ((tok = strsep(&next, "\n")) != NULL) {

		/* blank out and terminate */
		memset(centre_line, ' ', dwidth);
		centre_line[dwidth] = '\0';

		/* calculate start point and copy in */
		centre_start = dwidth / 2 - (strlen(tok) / 2);
		strncpy(&(centre_line[centre_start]), tok, dwidth);

		if (*dest == NULL)
			*dest = xstrdup(centre_line);
		else
			xasprintf(dest, "%s\n%s", *dest, centre_line);
	}

	free(centre_line);
	free(orig_copy);

	return (HGD_OK);
}

int
hgd_show_dialog(struct ui *u, const char *title, const char *msg, int secs)
{
	WINDOW			*bwin, *win;
	int			 x, y, h, w;
	char			*msg_centre;
	int			 ch = 0, again = 0;

	/* we will need to redisplay the dialog if we get a resize */
	do {
		again = 0;

		hgd_calc_dialog_win_dims(&y, &x, &h, &w);
		hgd_centre_dialog_text(&msg_centre, msg);

		DPRINTF(HGD_D_INFO, "Show dialog: '%s'", title);

		if ((bwin = newwin(h + 2, w + 2, y - 1, x - 1)) == NULL) {
			DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
			return (HGD_FAIL);
		}

		if ((win = newwin(h, w, y, x)) == NULL) {
			DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
			return (HGD_FAIL);
		}

		wattron(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
		wattron(bwin, COLOR_PAIR(HGD_CPAIR_DIALOG));

		wclear(win);
		wclear(bwin);

		wbkgd(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
		box(bwin, '|', '-');

		mvwprintw(bwin, 0, w / 2 - (strlen(title) / 2), title);
		mvwprintw(win, 1, 0, msg_centre);

		redrawwin(bwin);
		redrawwin(win);
		wrefresh(bwin);
		wrefresh(win);

		if (secs)
			sleep(secs);
		else
			ch = wgetch(win);

		if (ch == KEY_RESIZE) {
			DPRINTF(HGD_D_INFO, "redraw dialog");
			hgd_resize_app(u);
			again = 1;
		}

		delwin(win);
		delwin(bwin);

		free(msg_centre);

	} while(again);

	hgd_refresh_ui(u);

	return (HGD_OK);
}

int
hgd_set_statusbar_text(struct ui *u, char *fmt, ...)
{
	va_list			 ap;
	char			*buf;

	va_start(ap, fmt);
	if (vasprintf(&buf, fmt, ap) < 0) {
		DPRINTF(HGD_D_ERROR, "Can't allocate");
		return (HGD_FAIL);
	}

	free(u->status_str);
	u->status_str = buf;
	hgd_refresh_statusbar(u);

	return (HGD_OK);
}

/*
 * The "standard" statusbar that the user sees 99% of the time
 */
int
hgd_set_standard_statusbar_text(struct ui *u)
{
	return (hgd_set_statusbar_text(u,
	    "Connected >>> %s@%s:%d   Vote: %d", user, host, port, -1));
}


int hgd_ui_q_callback(void *arg, float progress)
{
	char				 bar[COLS+1];
	struct ui 			*u = (struct ui *) arg;
	int				 i, fill = COLS * progress;

	memset(bar, ' ', COLS);
	bar[COLS] = '\0';

	for (i = 0; i < fill; i++)
		bar[i] = '#';

	hgd_set_statusbar_text(u, "%s", bar);

	return (HGD_OK);
}

int
hgd_ui_queue_track(struct ui *u, char *filename)
{
	char			*full_path = NULL;
	char			*title = "[ File Upload ]";
	int			 ret = HGD_FAIL;
	WINDOW			*bwin = NULL, *win = NULL, *bar = NULL;
	int			 x, y, h, w;
	char			*msg_centre;
	struct hgd_ui_pbar	 pbar_struct;

	DPRINTF(HGD_D_INFO, "Upload track: %s", filename);

	xasprintf(&full_path, "%s/%s", u->cwd, filename);

	hgd_calc_dialog_win_dims(&y, &x, &h, &w);
	hgd_centre_dialog_text(&msg_centre, filename);

	if ((bwin = newwin(h + 2, w + 2, y - 1, x - 1)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
		goto clean;
	}

	if ((win = newwin(h, w, y, x)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise progress window");
		goto clean;
	}

#if 0
	if ((bar = newwin(1, w - 4, y+3, x+2)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not initialise progress bar");
		goto clean;
	}
#endif

	wattron(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
	wattron(bwin, COLOR_PAIR(HGD_CPAIR_DIALOG));

	wclear(win);
	wclear(bwin);
	//wclear(bar);

	wbkgd(win, COLOR_PAIR(HGD_CPAIR_DIALOG));
	wbkgd(bar, COLOR_PAIR(HGD_CPAIR_PBAR_BG));
	box(bwin, '|', '-');

	mvwprintw(bwin, 0, w / 2 - (strlen(title) / 2), title);
	mvwprintw(win, 1, 0, msg_centre);

	redrawwin(bwin);
	redrawwin(win);
	//redrawwin(bar);
	wrefresh(bwin);
	wrefresh(win);
	//wrefresh(bar);

	/* callback args */
#if 0
	pbar_struct.width = w - 4; 
	pbar_struct.win = bar;
#endif

	hgd_cli_queue_track(full_path, u, hgd_ui_q_callback);

	/* XXX */
	//hgd_resize_app(u);

	ret = HGD_OK;
clean:
	if (full_path)
		free(full_path);

	/* XXX work out why this flickers -- looks shit */
	if (ret == HGD_OK) 
		hgd_set_statusbar_text(u, "Upload of '%s' succesful", filename);
	else
		hgd_set_statusbar_text(u, "Upload of '%s' failed", filename);

	delwin(win);
	delwin(bwin);
	//delwin(bar);

	free(msg_centre);

	hgd_refresh_ui(u);

	return (ret);
}

/* uh oh, someone hit enter on the files menu! */
int
hgd_enter_on_files_menu(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Selected item on files menu");

	char			*new_cwd = NULL;
	ITEM			*item;
	struct dirent		*dirent;

	if ((item = current_item(u->content_menus[HGD_WIN_FILES])) == NULL) {
	    DPRINTF(HGD_D_WARN, "Could not get current item");
	    return (HGD_FAIL);
	}

	dirent = (struct dirent *) item_userptr(item);

	switch (dirent->d_type) {
	case DT_DIR:
		DPRINTF(HGD_D_INFO, "switch cwd: dirent->d_name");

		if (strcmp(dirent->d_name, "..") == 0)
			new_cwd = xstrdup(dirname(u->cwd));
		else
			xasprintf(&new_cwd, "%s/%s", u->cwd, dirent->d_name);

		free(u->cwd);
		u->cwd = new_cwd;

		break;
	default:
		hgd_ui_queue_track(u, dirent->d_name);
		break;
	};

	return (HGD_OK);
}

int
hgd_event_loop(struct ui *u)
{
	int			c;

	/* XXX catch C^c */
	while (1) {

		c = wgetch(u->content_wins[u->active_content_win]);
		switch(c) {
		case KEY_DOWN:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(u->content_menus[u->active_content_win],
			    REQ_UP_ITEM);
			break;
		case '\t':
			/* tab toggles toggle between files and playlist */
			if (u->active_content_win != HGD_WIN_PLAYLIST)
				hgd_switch_content(u, HGD_WIN_PLAYLIST);
			else
				hgd_switch_content(u, HGD_WIN_FILES);
			break;
		case '`':
			hgd_switch_content(u, HGD_WIN_CONSOLE);
			break;
		case KEY_RESIZE:
			/* fires magically when terminal is resized */
			hgd_resize_app(u);
			break;
		case '\n':
			if (u->active_content_win == HGD_WIN_FILES) {
				hgd_enter_on_files_menu(u);
				hgd_switch_content(u, HGD_WIN_FILES);
			}
		}

	}
}

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * see hgd-playd.c for how to remove need for stat.
	 */
	config_t		 cfg, *cf;
	int			 ret = HGD_OK;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL)
		return (HGD_OK);

	/* hgd_cfg_c_colours(cf, &colours_on); */
	hgd_cfg_crypto(cf, "hgdc", &crypto_pref);
	hgd_cfg_c_hostname(cf, &host);
	hgd_cfg_c_port(cf, &port);
	hgd_cfg_c_password(cf, &password, *config_locations);
	/* hgd_cfg_c_refreshrate(cf, &hud_refresh_speed); */
	hgd_cfg_c_username(cf, &user);
	hgd_cfg_c_debug(cf, &hgd_debug);

	config_destroy(cf);
	return (ret);
#else
	return (HGD_OK);
#endif
}

int
hgd_show_about(struct ui *u)
{
	char			*msg;

	xasprintf(&msg, "Welcome to nchgdc version %s!\n\n"
	    "http://hgd.theunixzoo.co.uk", HGD_VERSION);

	hgd_show_dialog(u, "[ Welcome to the Land of Forbidden Fruit! ]", msg, 0);
	free(msg);

	return (HGD_OK);
}

int
hgd_ui_connect(struct ui *u)
{
	hgd_set_statusbar_text(u, "Connecting >>> %s@%s:%d", user, host, port);

	if (hgd_setup_socket() != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Cannot setup socket");
		hgd_show_dialog(u, "[ Error ]", "Failed to connect", 0);
		return (HGD_FAIL);
	}

	hgd_set_statusbar_text(u,
	    "Connected, checking server version >>> %s@%s:%d",
	    user, host, port);

	/* check protocol matches the server before we continue */
	if (hgd_check_svr_proto() != HGD_OK) {
		hgd_show_dialog(u, "[ Error ]", "Protocol mismatch", 0);
		return (HGD_FAIL);
	}

	hgd_set_statusbar_text(u, "Connected, authenticating >>> %s@%s:%d",
	    user, host, port);

	if (hgd_client_login(sock_fd, ssl, user) != HGD_OK) {
		hgd_show_dialog(u, "[ Error ]", "Authentication Failed", 0);
		return (HGD_FAIL);
	}

	hgd_set_standard_statusbar_text(u);
	hgd_update_playlist_win(u);
	hgd_refresh_ui(u);

	return (HGD_OK);
}

int
main(int argc, char **argv)
{
	struct ui	u;
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2;

	hgd_debug = 3; /* XXX config file or getopt */

	host = xstrdup(HGD_DFL_HOST);
#ifdef HAVE_LIBCONFIG
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_CLI_CFG );
	config_path[2] = hgd_get_XDG_userprefs_location(hgdc);
#endif

	hgd_read_config(config_path + num_config);

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}

	if (init_log() != HGD_OK)
		hgd_exit_nicely();

	/* XXX proper dialog box needed */
	if (password == NULL) {
		password = xmalloc(HGD_MAX_PASS_SZ);
		if (readpassphrase("Password: ", password, HGD_MAX_PASS_SZ,
			    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
			DPRINTF(HGD_D_ERROR, "Can't read password");
			hgd_exit_nicely();
		}
	}

	initscr();

	cbreak();
	keypad(stdscr, TRUE);
	noecho();

	if (has_colors()) {
		if (start_color() == ERR)
			DPRINTF(HGD_D_WARN, "Could not initialise colour terminal");
	}

	/* XXX fall back implementations for B+W terms? */
	init_pair(HGD_CPAIR_BARS, COLOR_YELLOW, COLOR_BLUE);
	init_pair(HGD_CPAIR_SELECTED, COLOR_BLACK, COLOR_WHITE);
	init_pair(HGD_CPAIR_DIALOG, COLOR_BLACK, COLOR_CYAN);
	init_pair(HGD_CPAIR_PBAR_BG, COLOR_YELLOW, COLOR_BLACK);

	/* initialise top and bottom bars */
	if (hgd_init_titlebar(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_statusbar(&u) != HGD_OK)
		hgd_exit_nicely();

	/* and all content windows */
	if (hgd_init_files_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_console_win(&u) != HGD_OK)
		hgd_exit_nicely();
	if (hgd_init_playlist_win(&u) != HGD_OK)
		hgd_exit_nicely();

	/* start on the playlist */
	hgd_switch_content(&u, HGD_WIN_PLAYLIST);

	if (hgd_ui_connect(&u) != HGD_OK)
		hgd_exit_nicely();

	/* main event loop */
	DPRINTF(HGD_D_INFO, "nchgdc event loop starting");
	while (1)
		hgd_event_loop(&u);

	exit_ok = 1;
	hgd_exit_nicely();

	return 0;
}

