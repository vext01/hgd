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

#ifndef HGD_ADMIN_H
#define HGD_ADMIN_H

/*
 * these should not be taking char **args as though they were dynamic despatch
 * targets. That should be pushed up to the consumer level. XXX
 */
int			 hgd_acmd_user_add(char **args);
int			 hgd_acmd_user_add_prompt(char **args);
int			 hgd_acmd_user_del(char **args);
struct hgd_user_list	*hgd_acmd_user_list(char **args);
int			 hgd_acmd_user_list_print(char **args);
int			 hgd_change_user_perms(char *uname,
			    int perm_mask, uint8_t set);
int			 hgd_pause_track();
int			 hgd_skip_track();

#endif
