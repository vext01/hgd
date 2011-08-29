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
