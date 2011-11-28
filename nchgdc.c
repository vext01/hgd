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
#include <curses.h>
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
	"Console"
};

const char *test_playlist[] = {
	"Gunther.ogg",
	"Crabs.mp3",
	"Some longer file name with spaces.ogg",
	"Some track4",
	"Some track5",
	"Some track6",
	"Some track7",
	"Some track8",
	"Some track10",
	"Some track11",
	"Some track11",
	"Some track12",
	"Some track15",
	"Some track13",
	"Some track12",
	NULL
};

struct hgd_ui_log			logs;

void
hgd_exit_nicely()
{
	endwin();

	if (!exit_ok) {
		DPRINTF(HGD_D_ERROR, "nchgdc crashed or was interrupted");
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
	wprintw(u->status, fmt,  "User: edd\tHasVote: Yes");
	free (fmt);
}

void
hgd_refresh_ui(struct ui *u)
{
	refresh();

	redrawwin(u->content_wins[u->active_content_win]);
	wrefresh(u->content_wins[u->active_content_win]);

	hgd_update_titlebar(u);
	wrefresh(u->title);

	hgd_update_statusbar(u);
	wrefresh(u->status);
}

void
init_log()
{
	char *logfile = NULL;

	xasprintf(&logfile, "%s/%s/nchgdc.log",
	    getenv("HOME"), HGD_USR_CFG_DIR);

	DPRINTF(HGD_D_INFO, "UI logging to '%s'", logfile);
	if ((logs.wr = fopen(logfile, "w")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open write log: %s", SERROR);
		exit (1); /* XXX */
	}

	if ((logs.rd = fopen(logfile, "r")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Could not open read log: %s", SERROR);
		exit (1); /* XXX */
	}

	free(logfile);

	/* Redirect stderr here, so that DPRINTF can still work */
	close(fileno(stderr));
	dup(fileno(logs.wr));
}

void
hgd_update_titlebar(struct ui *u)
{
	char			*fmt = NULL, *title_str = NULL;

	DPRINTF(HGD_D_INFO, "Update titlebar window");

	wattron(u->title, COLOR_PAIR(HGD_CPAIR_BARS));

	xasprintf(&fmt, "%%-%ds", COLS);
	xasprintf(&title_str, "nchgdc-%s :: %s", HGD_VERSION,
	    window_names[u->active_content_win]);

	mvwprintw(u->title, 0, 0, fmt, title_str);

	free(title_str);
	free(fmt);
}

int
hgd_update_playlist_win(struct ui *u)
{
	/* XXX */
	return (HGD_OK);
}

int
hgd_update_files_win(struct ui *u)
{
	/* XXX */
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

	return (HGD_OK);
}

int
hgd_init_playlist_win(struct ui *u)
{
	ITEM			**items;
	int			  n_items, i;
	char			 *item_str;

	DPRINTF(HGD_D_INFO, "Initialise playlist window");

	/* make window */
	if ((u->content_wins[HGD_WIN_PLAYLIST] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to playlist content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_PLAYLIST], TRUE);

	/* and now populate the menu */
	n_items = ARRAY_SIZE(test_playlist);

	items = xcalloc(n_items, sizeof(ITEM *));
	for (i = 0; i < n_items - 1; i++) {
		DPRINTF(HGD_D_DEBUG, "Adding item \"%s\"", test_playlist[i]);

		hgd_prepare_item_string(&item_str, (char *) test_playlist[i]);

		items[i] = new_item(item_str, NULL);
		if (items[i] == NULL)
			DPRINTF(HGD_D_WARN, "Could not make new item: %s", SERROR);
	}

	u->content_menus[HGD_WIN_PLAYLIST] = new_menu(items);
	if (u->content_menus[HGD_WIN_PLAYLIST] == NULL)
			DPRINTF(HGD_D_ERROR, "Could not make menu");

	set_menu_win(u->content_menus[HGD_WIN_PLAYLIST], u->content_wins[HGD_WIN_PLAYLIST]);
	set_menu_mark(u->content_menus[HGD_WIN_PLAYLIST], "");
	set_menu_format(u->content_menus[HGD_WIN_PLAYLIST], LINES - 2, 1);
	set_menu_fore(u->content_menus[HGD_WIN_PLAYLIST], COLOR_PAIR(HGD_CPAIR_SELECTED));

	if ((post_menu(u->content_menus[HGD_WIN_PLAYLIST])) != E_OK)
		DPRINTF(HGD_D_ERROR, "Could not post menu");


	/* refresh handler */
	u->content_refresh_handler[HGD_WIN_PLAYLIST] = hgd_update_console_win;

	return (HGD_OK);
}

/* initialise the file browser content pane */
int
hgd_init_files_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise file browser window");

	if ((u->content_wins[HGD_WIN_FILES] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
		DPRINTF(HGD_D_ERROR, "Failed to initialise file browser content window");
		return (HGD_FAIL);
	}

	keypad(u->content_wins[HGD_WIN_FILES], TRUE);
	mvwprintw(u->content_wins[HGD_WIN_FILES], 0, 0, "Insert file browser here");
	mvwprintw(u->content_wins[HGD_WIN_FILES], 10, 0, "Ooooh - you touch my tralala");

	u->content_menus[HGD_WIN_FILES] = NULL; /* no menu */
	u->content_refresh_handler[HGD_WIN_FILES] = hgd_update_files_win;

	return (HGD_OK);
}

int
hgd_init_console_win(struct ui *u)
{
	DPRINTF(HGD_D_INFO, "Initialise console window");

	if ((u->content_wins[HGD_WIN_CONSOLE] = newwin(LINES - 2, COLS, 1, 0)) == NULL) {
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
	if (wresize(u->content_wins[HGD_WIN_FILES], HGD_POS_TITLE_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	/* update geometry of console window - no need to move, always (1,0) */
	if (wresize(u->content_wins[HGD_WIN_CONSOLE], HGD_POS_CONT_H, HGD_POS_CONT_W) != OK)
		DPRINTF(HGD_D_WARN, "Could not resize window: %s", SERROR);

	return (hgd_switch_content(u, u->active_content_win));
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
main(int argc, char **argv)
{
	struct ui	u;

	hgd_debug = 3; /* XXX config file or getopt */

	init_log();

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

	/* main event loop */
	DPRINTF(HGD_D_INFO, "nchgdc event loop starting");
	while (1)
		hgd_event_loop(&u);

	exit_ok = 1;
	hgd_exit_nicely();

	return 0;
}

