#!/bin/bash

# usage:
# /path/to/regenerate_hfi1_header.sh [hfi1.ko]

SCRIPT_PATH="${BASH_SOURCE[0]}"
ROOTDIR=$(readlink -m "$SCRIPT_PATH")
ROOTDIR=$(dirname "$ROOTDIR")
set -e -u

# static configuration-ish
declare -r DES_BIN="${ROOTDIR}/dwarf-extract-struct"
declare -r DES_SRC="${DES_BIN}.c"
declare -r HDR_PREFIX="${ROOTDIR}/../include/hfi1/hfi1_generated_"

error() {
	echo "$@" >&2
	exit 1
}

HFI1_KO="${1-$(modinfo -n hfi1)}" || \
	error "Could not find hfi1 module and no argument given. Usage: $0 [hfi1.ko]"


[[ "$DES_BIN" -nt "$DES_SRC" ]]			|| \
	gcc -o "$DES_BIN" -g -ldwarf "$DES_SRC"	|| \
	error "Could not compile, install libdwarf-devel ?"

"$DES_BIN" "$HFI1_KO" hfi1_pportdata 					\
	vls_operational > "${HDR_PREFIX}pportdata.h"

"$DES_BIN" "$HFI1_KO" hfi1_ctxtdata					\
	ctxt rcv_array_groups eager_base expected_count expected_base	\
	tid_group_list tid_used_list tid_full_list dd			\
		> "${HDR_PREFIX}ctxtdata.h"

"$DES_BIN" "$HFI1_KO" hfi1_devdata					\
	per_sdma sdma_pad_phys sdma_map pport chip_rcv_array_count	\
	kregbase1 piobase physaddr rcvarray_wc default_desc1 flags	\
	sc2vl events first_dyn_alloc_ctxt chip_rcv_contexts \
	> "${HDR_PREFIX}devdata.h"

"$DES_BIN" "$HFI1_KO" hfi1_filedata					\
	uctxt pq cq dd subctxt entry_to_rb tid_lock tid_used \
	invalid_tids invalid_tid_idx invalid_lock \
		> "${HDR_PREFIX}filedata.h"

"$DES_BIN" "$HFI1_KO" sdma_state					\
	current_state go_s99_running previous_state\
		> "${HDR_PREFIX}sdma_state.h"

"$DES_BIN" "$HFI1_KO" sdma_engine					\
	dd tail_lock desc_avail tail_csr flushlist flushlist_lock \
	descq_head descq_tail descq_cnt state sdma_shift sdma_mask\
	descq tx_ring tx_tail head_lock descq_full_count ahg_bits\
	this_idx \
		> "${HDR_PREFIX}sdma_engine.h"

"$DES_BIN" "$HFI1_KO" user_sdma_request	\
	data_iovs pq cq txps info hdr tidoffset data_len \
	iov_idx sent seqnum has_error koffset tididx \
	tids n_tids sde ahg_idx iovs seqcomp seqsubmitted \
		> "${HDR_PREFIX}user_sdma_request.h"

"$DES_BIN" "$HFI1_KO" user_sdma_txreq	\
	hdr txreq list req flags busycount seqnum \
		> "${HDR_PREFIX}user_sdma_txreq.h"

"$DES_BIN" "$HFI1_KO" hfi1_user_sdma_pkt_q	\
	dd req_in_use reqs n_reqs state n_max_reqs \
		> "${HDR_PREFIX}hfi1_user_sdma_pkt_q.h"
