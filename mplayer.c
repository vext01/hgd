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

/* PLEASE DON'T PUT ANY DATABASE CODE HERE -- SQLITE3 LINKAGE FORBIDDEN */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "config.h"
#ifdef HAVE_PYTHON
#include "py.h" /* defines _GNU_SOURCE comes before stdio.h */
#else
#define _GNU_SOURCE
#endif

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hgd.h"
#include "mplayer.h"
#include "db.h"

char			*mplayer_fifo_path = 0;

int
hgd_mplayer_pipe_send(char *what)
{
	FILE			*pipe = NULL;
	int			 ret = HGD_FAIL;
	struct stat		 st;

	if (mplayer_fifo_path == NULL)
		xasprintf(&mplayer_fifo_path, "%s/%s",
		    state_path, HGD_MPLAYER_PIPE_NAME);

	if (stat(mplayer_fifo_path, &st) < 0) {
		if (errno == ENOENT) {
			/* no pipe = not playing */
			DPRINTF(HGD_D_ERROR, "No track is playing");
			ret = HGD_FAIL_NOPLAY;
		} else {
			DPRINTF(HGD_D_ERROR, "Pipe failure: %s", SERROR);
			ret = HGD_FAIL;
		}
		goto clean;
	}

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

	return (ret);
}

/*
 * make a fifo that mplayer can take commands from
 */
int
hgd_make_mplayer_input_fifo(void)
{
	if (mkfifo(mplayer_fifo_path, 0600) < 0) {
		/* pipe should not exist, but no harm if it does */
		if (errno != EEXIST) {
			DPRINTF(HGD_D_WARN,
			    "Failed to create mplayer input fifo: %s", SERROR);
			return (HGD_FAIL);
		}
	}

	return (HGD_OK);
}

int
hgd_pause_track()
{
	return (hgd_mplayer_pipe_send("pause\n"));
}

int
hgd_skip_track()
{
	return (hgd_mplayer_pipe_send("stop\n"));
}

/*
 * Check MPlayer seems to be present and sane
 */
int
hgd_check_mplayer_present()
{
	FILE			*pipe = NULL;
	char			 vstr[HGD_MAX_MPLAYER_VSTR];

	if ((pipe = popen("mplayer -v", "r")) == NULL) {
		DPRINTF(HGD_D_ERROR, "Unable to popen to determine mplayer version");
		return (HGD_FAIL);
	}

	/* we should always get a line and never get EOF */
	if ((fgets(vstr, HGD_MAX_MPLAYER_VSTR, pipe)) == NULL) {
		DPRINTF(HGD_D_ERROR, "MPlayer did not reply with a version string");
		return (HGD_FAIL);
	}

	vstr[strlen(vstr) - 1] = '\0';

	DPRINTF(HGD_D_INFO, "MPlayer version is: '%s'", vstr);

	if (strncmp("MPlayer", vstr, strlen("MPlayer")) != 0) {
		DPRINTF(HGD_D_ERROR, "MPlayer version string is kinda weird");
		return (HGD_FAIL);
	}

	fclose(pipe);

	return (HGD_OK);
}
