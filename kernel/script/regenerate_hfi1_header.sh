#!/bin/bash

# usage:
# /path/to/regenerate_hfi1_header.sh [hfi1.ko]

SCRIPT_PATH="${BASH_SOURCE[0]}"
ROOTDIR=$(readlink -m "$SCRIPT_PATH")
ROOTDIR=$(dirname "$ROOTDIR")
set -e

# static configuration-ish
declare -r DES_BIN="${ROOTDIR}/dwarf-extract-struct"
declare -r DES_SRC="${DES_BIN}.c"
declare -r HDR="${ROOTDIR}/../include/hfi1/hfi1_generated_structs.h"

error() {
	echo "$@" >&2
	exit 1
}

HFI1_KO="${1-$(modprobe -n hfi1)}" || \
	error "Could not find hfi1 module and no argument given. Usage: $0 [hfi1.ko]"


[[ "$DES_BIN" -nt "$DES_SRC" ]]			|| \
	gcc -o "$DES_BIN" -g -ldwarf "$DES_SRC"	|| \
	error "Could not compile, install libdwarf-devel ?"

"$DES_BIN" "$HFI1_KO" hfi1_pportdata vls_operational > "$HDR"

"$DES_BIN" "$HFI1_KO" hfi1_ctxtdata					\
	ctxt rcv_array_groups eager_base expected_count expected_base	\
	tid_group_list tid_used_list tid_full_list dd >> "$HDR"

"$DES_BIN" "$HFI1_KO" hfi1_devdata					\
	per_sdma sdma_pad_phys sdma_map pport chip_rcv_array_count	\
	kregbase1 piobase physaddr rcvarray_wc default_desc1 flags	\
	sc2vl >> "$HDR"
