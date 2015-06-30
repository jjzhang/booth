/*
 * Copyright (C) 2015 Dejan Muhamedagic <dejan@hello-penguin.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "auth.h"

/* calculate the HMAC of the message in data and store it in result
 * it is up to the caller to make sure that there's enough space
 * at result for the MAC
 */
int calc_hmac(const void *data, size_t datalen,
	hashid hid, unsigned char *result, char *key, int keylen)
{
	MHASH td;
	size_t block_size;

	block_size = mhash_get_hash_pblock(hid);
	if (!block_size)
		return -1;

	td = mhash_hmac_init(hid, key, keylen, block_size);
	if (!td)
		return -1;

	(void)mhash(td, data, datalen);
	if (mhash_hmac_deinit(td, result))
		return -1;

	return 0;
}

/* test HMAC
 */
int verify_hmac(const void *data, size_t datalen,
	hashid hid, unsigned char *hmac, char *key, int keylen)
{
	MHASH td;
	unsigned char *our_hmac = NULL;
	int rc = -1;

	td = mhash_hmac_init(hid, key, keylen,
		mhash_get_hash_pblock(hid));
	if (!td)
		return -1;

	our_hmac = malloc(mhash_get_block_size(hid));
	if (!our_hmac)
		return -1;

	(void)mhash(td, data, datalen);
	if (mhash_hmac_deinit(td, our_hmac))
		goto out_free;

	rc = memcmp(our_hmac, hmac, mhash_get_block_size(hid));

out_free:
	if (our_hmac)
		free(our_hmac);
	return rc;
}
