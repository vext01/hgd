
#define _GNU_SOURCE	/* linux */

#include <stdio.h>
#include <curses.h>
#include <stdlib.h>
#include <menu.h>
#include <err.h>

#define HGD_VERSION		"x.xx"

#define HGD_CPAIR_BARS		1
#define HGD_CPAIR_SELECTED	2

struct ui {
	WINDOW		*title;		/* title bar */
	WINDOW		*content;	/* main pane in the middle */
	WINDOW		*status;	/* status bar */
	MENU		*menu;
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

FILE			*hlog;

void
hgd_refresh_ui(struct ui *u)
{
	refresh();
	post_menu(u->menu);
	wrefresh(u->content);
	wrefresh(u->title);
	wrefresh(u->status);

}

#define LOGFILE		"tutti.log"
void
init_log()
{
	if ((hlog = fopen(LOGFILE, "w")) == NULL)
		err(1, "init logfile");
}

void
dolog(char *msg)
{
	if (fprintf(hlog, "%s\n", msg) == -1) {
		endwin();
		err(1, "failed to log");
	}
}

void
fail(char *msg)
{
	endwin();
	fprintf(stderr, "%s\n", msg);
	exit (1);
}

void
hgd_init_titlebar(struct ui *u)
{
	char			*fmt = NULL;

	if ((u->title = newwin(1, COLS, 0, 0)) == NULL)
		fail("cant make win");

	wattron(u->title, COLOR_PAIR(HGD_CPAIR_BARS));
	asprintf(&fmt, "%%-%ds%%s", COLS);
	wprintw(u->title, fmt,  "Tutti-"HGD_VERSION, " :: Playlist");

	free (fmt);
}

void
hgd_init_statusbar(struct ui *u)
{
	char			*fmt = NULL;

	if ((u->status = newwin(1, COLS, LINES - 1, 0)) == NULL)
		fail("cant make win");

	wattron(u->status, COLOR_PAIR(HGD_CPAIR_BARS));
	asprintf(&fmt, "%%-%ds", COLS);
	wprintw(u->status, fmt,  "User: edd\tHasVote: Yes");
	free (fmt);
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
void
hgd_init_content_win(struct ui *u)
{
	ITEM			**items;
	int			  num, i;

	num = ARRAY_SIZE(test_playlist);

	items = calloc(num, sizeof(ITEM *));
	for (i = 0; i < num; i++)
		items[i] = new_item(test_playlist[i], NULL);

	u->menu = new_menu(items);
	u->content = newwin(LINES - 2, COLS, 1, 1);
	keypad(u->content, TRUE);
	set_menu_win(u->menu, u->content);
	set_menu_mark(u->menu, "");
	set_menu_format(u->menu, LINES - 2, 1);
	set_menu_fore(u->menu, COLOR_PAIR(HGD_CPAIR_SELECTED));
}

int
main(int argc, char **argv)
{
	struct ui	u;
	int		c;

	init_log();

	initscr();

	cbreak();
	keypad(stdscr, TRUE);
	noecho();

	if (!has_colors())
		fail("no colors");

	if (start_color() == ERR)
		fail("cant start colours");

	init_pair(HGD_CPAIR_BARS, COLOR_YELLOW, COLOR_BLUE);
	init_pair(HGD_CPAIR_SELECTED, COLOR_BLACK, COLOR_WHITE);

	hgd_init_titlebar(&u);
	hgd_init_statusbar(&u);
	hgd_init_content_win(&u);

	/* main event loop */
	while (1) {
		hgd_refresh_ui(&u);

		c = wgetch(u.content);
		switch(c) {
		case KEY_DOWN:
			menu_driver(u.menu, REQ_DOWN_ITEM);
			break;
		case KEY_UP:
			menu_driver(u.menu, REQ_UP_ITEM);
			break;
		}
	}

    	getch();
	endwin();

	/* XXX close log */

	return 0;
}
