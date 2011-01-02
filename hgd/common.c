#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "hgd.h"

void hgd_free_playlist_item(struct hgd_playlist_item *i)
{
	free(i->filename);
	free(i->user);
	free(i);
}

void *
xmalloc(size_t sz)
{
	void			*ptr;

	ptr = malloc(sz);
	if (!ptr)
		fprintf(stderr, "%s: could not allocate\n", __func__);

	return ptr;
}

int
xasprintf(char **buf, char *fmt, ...)
{
	va_list			ap;
	int			ret;

	va_start(ap, fmt);
	ret = vasprintf(buf, fmt, ap);

	if (ret == -1)
		fprintf(stderr, "%s: can't allocate", __func__);

	return ret;
}
