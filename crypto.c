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
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "config.h"
#include "hgd.h"

/* This file is non-networking crypto stuff */

/*
 * Use openssl to make a SHA1 hex hash of a string.
 * User must free.
 */
char *
hgd_sha1(const char *msg, const char *salt)
{
	EVP_MD_CTX md_ctx;
	const EVP_MD *md;
	char *concat, *no_salt = "";
	unsigned char hash[EVP_MAX_MD_SIZE + 1];
	unsigned int hash_len;

	if (salt == NULL)
		salt = no_salt;

	memset(hash, 0, EVP_MAX_MD_SIZE + 1);

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("sha1");

	if (!md) {
		DPRINTF(HGD_D_WARN, "EVP_get_digestbyname");
		return (NULL);
	}

	EVP_MD_CTX_init(&md_ctx);

	if (!EVP_DigestInit_ex(&md_ctx, md, NULL)) {
		DPRINTF(HGD_D_WARN, "EVP_DigestInit_ex");
		return (NULL);
	}

	xasprintf(&concat, "%s%s", salt, msg);
	if (!EVP_DigestUpdate(&md_ctx, concat, strlen(concat))) {
		DPRINTF(HGD_D_WARN, "EVP_DigestInit_ex");
		free(concat);
		return (NULL);
	}
	free(concat);

	if (!EVP_DigestFinal_ex(&md_ctx, hash, &hash_len)) {
		DPRINTF(HGD_D_WARN, "EVP_DigestInit_ex");
		return (NULL);
	}

	EVP_MD_CTX_cleanup(&md_ctx);

	return (hgd_bytes_to_hex(hash, hash_len));
}
