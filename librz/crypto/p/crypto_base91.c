// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base91_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base91_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base91_use(const char *algo) {
	return algo && !strcmp(algo, "base91");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf || len < 1) {
		return false;
	}

	int olen;
	ut8 *obuf;
	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		// rz_base91_encode() takes no output-size parameter, so the caller
		// must pre-size obuf correctly: base91 emits 2 output characters
		// per 13 bits of input in the worst case (16 chars per 13/8 input
		// bytes), plus up to 2 more for the final partial-byte flush. A
		// fixed-size buffer here (the previous code used a constant 32768
		// regardless of len) overflows for any input whose encoded size
		// exceeds that constant.
		int cap = (len * 16 + 12) / 13 + 2;
		obuf = malloc(cap);
		if (!obuf) {
			return false;
		}
		olen = rz_base91_encode((char *)obuf, (const ut8 *)buf, len);
	} else if (cry->dir == 1) {
		// Decoding only ever shrinks the data (base91 expands on encode),
		// so len bytes is always enough.
		obuf = malloc(len + 2);
		if (!obuf) {
			return false;
		}
		olen = rz_base91_decode(obuf, (const char *)buf, len);
	} else {
		return false;
	}
	rz_crypto_append(cry, obuf, olen);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_base91 = {
	.name = "base91",
	.author = "rakholiyajenish.07",
	.license = "LGPL-3",
	.description = "Base91 encoder/decoder",
	.set_key = base91_set_key,
	.get_key_size = base91_get_key_size,
	.use = base91_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base91,
	.version = RZ_VERSION
};
#endif
