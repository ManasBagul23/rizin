// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf_strtab.h"
#include "elf.h"

RZ_BORROW const char *Elf_(rz_bin_elf_strtab_get)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index) {
	rz_return_val_if_fail(strtab, false);

	if (!Elf_(rz_bin_elf_strtab_has_index)(strtab, index)) {
		return NULL;
	}

	return strtab->data + index;
}

RZ_OWN RzBinElfStrtab *Elf_(rz_bin_elf_strtab_new)(RZ_NONNULL ELFOBJ *bin, ut64 offset, ut64 size) {
	rz_return_val_if_fail(bin, NULL);

	if (!size || !Elf_(rz_bin_elf_check_array)(bin, offset, size, sizeof(ut8))) {
		RZ_LOG_WARN("Invalid strtab at 0x%" PFMT64x " (check array failed).\n", offset);
		return NULL;
	}

	RzBinElfStrtab *result = RZ_NEW(RzBinElfStrtab);
	if (!result) {
		return NULL;
	}

	result->size = size;
	result->data = RZ_NEWS(char, size);
	if (!result->data) {
		Elf_(rz_bin_elf_strtab_free)(result);
		return NULL;
	}

	// rz_buf_read_at() returns the number of bytes actually read (0..size),
	// not just a negative error code; a short read (e.g. a truncated file
	// whose strtab size claims more bytes than remain) must be rejected
	// too, since result->data is RZ_NEWS()-allocated (unzeroed) and an
	// unfilled tail would otherwise leak leftover heap bytes through
	// rz_bin_elf_strtab_get()/_get_dup().
	if (rz_buf_read_at(bin->b, offset, (ut8 *)result->data, size) != (st64)size) {
		Elf_(rz_bin_elf_strtab_free)(result);
		return NULL;
	}

	if (result->data[0] != '\0' || result->data[size - 1] != '\0') {
		RZ_LOG_WARN("String table at 0x%" PFMT64x " should start and end by a NULL byte\n", offset);
		Elf_(rz_bin_elf_strtab_free)(result);
		return NULL;
	}

	return result;
}

RZ_OWN char *Elf_(rz_bin_elf_strtab_get_dup)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index) {
	rz_return_val_if_fail(strtab, NULL);

	if (!Elf_(rz_bin_elf_strtab_has_index)(strtab, index)) {
		return NULL;
	}

	char *result = rz_str_dup(strtab->data + index);
	if (!result) {
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_strtab_has_index)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index) {
	rz_return_val_if_fail(strtab, false);
	return index < strtab->size;
}

void Elf_(rz_bin_elf_strtab_free)(RzBinElfStrtab *ptr) {
	if (!ptr) {
		return;
	}

	free(ptr->data);
	free(ptr);
}
