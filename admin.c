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

#include <sqlite3.h>
#include <openssl/rand.h>

#include "admin.h"
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

	if (db == NULL)
		db = hgd_open_db(db_path, 0);
	if (db == NULL)
		return (HGD_FAIL);

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

	if (hgd_readpassphrase_confirmed(pass, NULL) != HGD_OK)
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
	int			 i, ret = HGD_FAIL;

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	if (hgd_user_list(&list) != HGD_OK)
		goto clean;

	for (i = 0; i < list->n_users; i++) {
		printf("%s (admin=%d)\n",
		    list->users[i]->name, list->users[i]->perms);
	}

	ret = HGD_OK;
clean:
	if (list != NULL) {
		hgd_free_user_list(list);
		free(list);
	}

	return (ret);
}

int
hgd_user_list(struct hgd_user_list **list)
{
	int		ret = HGD_FAIL;

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	if ((*list = hgd_get_all_users()) == NULL) {
		DPRINTF(HGD_D_WARN, "Failed to get userlist");
		goto clean;
	}

	ret = HGD_OK;
clean:
	return (ret);
}

/*
 * change 'user' permission, turn on/off (set=1, set=0), the permission
 * indicated by 'perm_mask'.
 */
int
hgd_change_user_perms(char *uname, int perm_mask, uint8_t set)
{
	struct hgd_user		user;
	int			ret = HGD_FAIL, new_perms = 0;

	memset(&user, 0, sizeof(struct hgd_user));

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	if (hgd_get_user(uname, &user) == HGD_FAIL_NOUSER) {
		DPRINTF(HGD_D_ERROR, "User %s does not exist.", user.name);
		goto clean;
	}

	/* turn on/off the correct bit */
	if (set)
		new_perms = user.perms | perm_mask;
	else
		new_perms = user.perms & (~perm_mask);

	/* if the perms didnt change, warn */
	if (new_perms == user.perms) {
		DPRINTF(HGD_D_WARN, "Permissions unchanged.");
		ret = HGD_FAIL_PERMNOCHG;
		goto clean;
	}

	/* otherwise, update */
	user.perms = new_perms;
	if (hgd_update_user(&user) != HGD_OK)
		goto clean;

	ret = HGD_OK;
clean:
	if (user.name)
		free(user.name);

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
