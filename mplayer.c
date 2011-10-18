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
		    HGD_DFL_DIR, HGD_MPLAYER_PIPE_NAME);

	if (stat(mplayer_fifo_path, &st) < 0) {
		if (errno == ENOENT) { 
			/* no pipe = not playing */
			DPRINTF(HGD_D_ERROR, "No track is playing");
			ret = HGD_ERR_MPLAYER_NOTPLAYING;
		} else {
			DPRINTF(HGD_D_ERROR, "Pipe failure: %s", SERROR);
			ret = HGD_ERR_MPLAYER_PIPE;
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
hgd_play_track(struct hgd_playlist_item *t, uint8_t purge_fs, uint8_t purge_db)
{
	int			status = 0, pid, ret = HGD_FAIL;
	char			*ipc_path = 0, *pipe_arg = 0;
	FILE			*ipc_file;
	struct stat		st;

	DPRINTF(HGD_D_INFO, "Playing '%s' for '%s'", t->filename, t->user);
	if (hgd_mark_playing(t->id) == HGD_FAIL)
		goto clean;

	/*
	 * We will write away the tid of the playing file
	 * hgd-netd uses this to check the user is voting off the track
	 * they think they are.
	 */
	xasprintf(&ipc_path, "%s/%s", state_path, HGD_PLAYING_FILE);

	/* first check the file is non-existent */
	if (stat(ipc_path, &st) < 0) {
		if (errno != ENOENT) {
			DPRINTF(HGD_D_ERROR,
			    "stale tid file: %s: %s", ipc_path, SERROR);
			goto clean;
		}
	} else {
		DPRINTF(HGD_D_ERROR, "stale tid file: %s" , ipc_path);
		goto clean;
	}

	if (hgd_file_open_and_lock(ipc_path, F_WRLCK, &ipc_file) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Can't open+lock '%s'", ipc_path);
		goto clean;
	}

	/* try to be secure */
	if (chmod(ipc_path, S_IRUSR | S_IWUSR) != 0)
		DPRINTF(HGD_D_WARN, "Can't secure ipc file: %s", SERROR);

	/* write away tid of current track to a file for hgd-netd */
	if (fprintf(ipc_file, "%d", t->id) < 0) {
		DPRINTF(HGD_D_ERROR, "Failed to write out tid: %s", SERROR);
		goto clean;
	}

	/* unlock */
	if (hgd_file_unlock_and_close(ipc_file) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "failed to unlock");
		goto clean;
	}

#ifdef HAVE_PYTHON
	hgd_execute_py_hook("pre_play");
#endif

	if (hgd_make_mplayer_input_fifo() != HGD_OK)
		goto clean;

	xasprintf(&pipe_arg, "file=%s", mplayer_fifo_path);

	pid = fork();
	if (!pid) {

		/* close stdin, or mplayer catches keyboard shortcuts */
		fclose(stdin);

		/* child - your the d00d who will play this track */
		execlp("mplayer", "mplayer", "-really-quiet", "-slave",
		    "-input", pipe_arg, t->filename,
		    (char *) NULL);

		/* if we get here, the shit hit the fan with execlp */
		DPRINTF(HGD_D_ERROR, "execlp() failed");
		hgd_exit_nicely(); /* child should always exit */
	} else {
		DPRINTF(HGD_D_INFO,
		    "Mplayer spawned, waiting to finish: pid=%d", pid);

		if (waitpid(pid, &status, 0) < 0) {
			/* it is ok for this to fail if we are restarting */
			if (restarting || dying) {
				kill(pid, SIGINT);
			}
			DPRINTF(HGD_D_WARN, "Could not wait(): %s", SERROR);
		}

		/* unlink ipc file */
		if (hgd_file_open_and_lock(
		    ipc_path, F_WRLCK, &ipc_file) != HGD_OK) {
			DPRINTF(HGD_D_ERROR, "Can't open+lock '%s'", ipc_path);
			goto clean;
		}

		if (unlink(ipc_path) < 0) {
			DPRINTF(HGD_D_ERROR, "can't unlink ipc file %s: %s",
			    ipc_path, SERROR);
			goto clean;
		}

		if (hgd_file_unlock_and_close(ipc_file) != HGD_OK) {
			DPRINTF(HGD_D_ERROR, "failed to unlock+close %s: %s",
			    ipc_path, SERROR);
		}

		/* unlink input pipe */
		if (unlink(mplayer_fifo_path) < 0)
			DPRINTF(HGD_D_WARN,
			    "Could not unlink mplayer input fifo %s", SERROR);

		/* unlink media (but not if restarting, we replay the track) */
		if ((!restarting) && (!dying)
		    && (purge_fs) && (unlink(t->filename) < 0)) {
			DPRINTF(HGD_D_DEBUG,
			    "Deleting finished: %s", t->filename);
			DPRINTF(HGD_D_WARN, "Can't unlink '%s'", ipc_path);
		}
	}
#ifdef HAVE_PYTHON
	hgd_execute_py_hook("post_play");
#endif

	DPRINTF(HGD_D_DEBUG, "Finished playing (exit %d)", status);

	/* if we are restarting, we replay the track on restart */
	if ((!restarting) && (!dying) &&
	    (hgd_mark_finished(t->id, purge_db) == HGD_FAIL))
		DPRINTF(HGD_D_WARN,
		    "Could not purge/mark finished -- trying to continue");

	ret = HGD_OK;

clean:
	if (pipe_arg)
		free(pipe_arg);
	if (ipc_path)
		free(ipc_path);

	return (ret);
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
