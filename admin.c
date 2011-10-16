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
hgd_user_add(char *user, char *pass)
{
	unsigned char		 salt[HGD_SHA_SALT_SZ];
	char			*salt_hex = NULL, *hash_hex = NULL;
	int			 ret = HGD_FAIL;

	char			salt_ascii[HGD_SHA_SALT_SZ * 2 + 1];
	char			hash_ascii[HGD_SHA_SALT_SZ * 2 + 1];

	DPRINTF(HGD_D_INFO, "Adding user '%s'", user);

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	memset(salt, 0, HGD_SHA_SALT_SZ);
	if (RAND_bytes(salt, HGD_SHA_SALT_SZ) != 1) {
		DPRINTF(HGD_D_ERROR, "can not generate salt");
		goto clean;
	}

	salt_hex = hgd_bytes_to_hex(salt, HGD_SHA_SALT_SZ);
	hgd_bytes_to_hex_buf(salt_hex, salt_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new user's salt '%s'", salt_ascii);

	hash_hex = hgd_sha1(pass, salt_hex);
	memset(pass, 0, strlen(pass));
	hgd_bytes_to_hex_buf(hash_hex, hash_ascii, HGD_SHA_SALT_SZ);
	DPRINTF(HGD_D_DEBUG, "new_user's hash '%s'", hash_ascii);

	ret = hgd_user_add_db(user, salt_hex, hash_hex);
clean:
	if (salt_hex)
		free(salt_hex);
	if (hash_hex)
		free(hash_hex);

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
hgd_user_mod_perms(char *uname, int perm_mask, uint8_t set)
{
	struct hgd_user		user;
	int			ret = HGD_FAIL, new_perms = 0;

	memset(&user, 0, sizeof(struct hgd_user));

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	if (hgd_get_user(uname, &user) == HGD_FAIL_USRNOEXIST) {
		DPRINTF(HGD_D_ERROR, "User %s does not exist.", user.name);
		ret = HGD_FAIL_USRNOEXIST;
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
	ret = hgd_user_mod_perms_db(&user);
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
