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

#include "admin.h"

#include <sqlite3.h>
#include <openssl/rand.h>
#include "hgd.h"
#include "db.h"
#include "mplayer.h"

int
hgd_acmd_user_add(char **args)
{
	unsigned char		 salt[HGD_SHA_SALT_SZ];
	char			*salt_hex, *hash_hex;
	char			*user = args[0], *pass = args[1];
	int			 ret = HGD_OK;

	char			salt_ascii[HGD_SHA_SALT_SZ * 2 + 1];
	char			hash_ascii[HGD_SHA_SALT_SZ * 2 + 1];

	DPRINTF(HGD_D_INFO, "Adding user '%s'", user);

	memset(salt, 0, HGD_SHA_SALT_SZ);
	if (RAND_bytes(salt, HGD_SHA_SALT_SZ) != 1) {
		DPRINTF(HGD_D_ERROR, "can not generate salt");
		return (HGD_FAIL);
	}

	salt_hex = hgd_bytes_to_hex(salt, HGD_SHA_SALT_SZ);
	hgd_bytes_to_hex_buf(salt_hex, salt_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new user's salt '%s'", salt_ascii);

	hash_hex = hgd_sha1(pass, salt_hex);
	memset(pass, 0, strlen(pass));
	hgd_bytes_to_hex_buf(hash_hex, hash_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new_user's hash '%s'", hash_ascii);

	if (hgd_add_user(args[0], salt_hex, hash_hex) != HGD_OK)
		ret = HGD_FAIL;

	free(salt_hex);
	free(hash_hex);
	
	return (ret);
}


int
hgd_acmd_user_add_prompt(char **args)
{
	char			 pass[HGD_MAX_PASS_SZ];
	char			*new_args[2];

	if (db == NULL)
		db = hgd_open_db(db_path, 0);
	if (db == NULL)
		return (HGD_FAIL);

	if (hgd_readpassphrase_confirmed(pass) != HGD_OK)
		return (HGD_FAIL);

	new_args[0] = args[0];
	new_args[1] = pass;

	return (hgd_acmd_user_add(new_args));
}

int
hgd_acmd_user_del(char **args)
{
	if (db == NULL)
		db = hgd_open_db(db_path, 0);
	if (db == NULL)
		return (HGD_FAIL);

	if (hgd_delete_user(args[0]) != HGD_OK)
		return (HGD_FAIL);

	return (HGD_OK);
}
int
hgd_acmd_user_list_print(char **args)
{
	struct hgd_user_list *list;
	int			 i;
	
	list = hgd_acmd_user_list(args);

	for (i = 0; i < list->n_users; i++)
		printf("%s\n", list->users[i]->name);

	hgd_free_user_list(list);
	free(list);

	return (HGD_OK);
}


struct hgd_user_list*
hgd_acmd_user_list(char **args)
{
	struct hgd_user_list	*list;

	(void) args;

	if (db == NULL)
		db = hgd_open_db(db_path, 0);
	if (db == NULL)
		return (HGD_FAIL);

	return list = hgd_get_all_users();
}

int
hgd_acmd_pause(char **args)
{
	(void) args;

	return (hgd_mplayer_pipe_send("pause\n"));
}

int
hgd_acmd_skip(char **args)
{
	(void) args;

	return (hgd_mplayer_pipe_send("stop\n"));
}
