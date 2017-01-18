/*-
 *   BSD LICENSE
 *
 *   Copyright(c) Broadcom Limited.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Broadcom Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_malloc.h>

#include "bnxt.h"
#include "bnxt_cpr.h"
#include "bnxt_hwrm.h"
#include "bnxt_ring.h"
#include "hsi_struct_def_dpdk.h"

/*
 * Async event handling
 */
void bnxt_handle_async_event(struct bnxt *bp,
			     struct cmpl_base *cmp)
{
	struct hwrm_async_event_cmpl *async_cmp =
				(struct hwrm_async_event_cmpl *)cmp;
	uint16_t event_id = rte_le_to_cpu_16(async_cmp->event_id);

	/* TODO: HWRM async events are not defined yet */
	/* Needs to handle: link events, error events, etc. */
	switch (event_id) {
	case HWRM_ASYNC_EVENT_CMPL_EVENT_ID_LINK_STATUS_CHANGE:
	case HWRM_ASYNC_EVENT_CMPL_EVENT_ID_LINK_SPEED_CHANGE:
	case HWRM_ASYNC_EVENT_CMPL_EVENT_ID_LINK_SPEED_CFG_CHANGE:
		bnxt_link_update_op(bp->eth_dev, 0);
		break;
	default:
		RTE_LOG(ERR, PMD, "handle_async_event id = 0x%x\n", event_id);
		break;
	}
}

void bnxt_handle_fwd_req(struct bnxt *bp, struct cmpl_base *cmpl)
{
	struct hwrm_exec_fwd_resp_input *fwreq;
	struct hwrm_fwd_req_cmpl *fwd_cmpl = (struct hwrm_fwd_req_cmpl *)cmpl;
	struct input *fwd_cmd;
	uint16_t vf_id;
	uint16_t req_len;

	if (bp->pf.active_vfs <= 0) {
		RTE_LOG(ERR, PMD, "Forwarded VF with no active VFs\n");
		return;
	}

	/* Qualify the fwd request */
	vf_id = rte_le_to_cpu_16(fwd_cmpl->source_id);

	/* TODO: req_len is always 128, is there a way to get the actual request length? */
	req_len = (rte_le_to_cpu_16(fwd_cmpl->req_len_type) & HWRM_FWD_REQ_CMPL_REQ_LEN_MASK) >>
	                                                      HWRM_FWD_REQ_CMPL_REQ_LEN_SFT;
	if (req_len > sizeof(fwreq->encap_request))
		req_len = sizeof(fwreq->encap_request);

	/* Locate VF's forwarded command */
	fwd_cmd = (struct input *)((uint8_t *)bp->pf.vf_req_buf +
		   ((vf_id - bp->pf.first_vf_id) * HWRM_MAX_REQ_LEN));
	/* Force the target ID to the source VF */
	fwd_cmd->target_id = rte_cpu_to_le_16(vf_id);

	if (vf_id < bp->pf.first_vf_id || vf_id >= (bp->pf.first_vf_id) + bp->pf.active_vfs) {
		RTE_LOG(ERR, PMD,
			"FWD req's source_id 0x%x out of range 0x%x - 0x%x (%d %d)\n",
			vf_id, bp->pf.first_vf_id,
			(bp->pf.first_vf_id) + bp->pf.active_vfs - 1, bp->pf.first_vf_id, bp->pf.active_vfs);
		goto reject;
	}

	/* TODO: Call "mailbox" callback if necessary */

	/* Forward */
	bnxt_hwrm_exec_fwd_resp(bp, vf_id, fwd_cmd, req_len);
	return;

reject:
	bnxt_hwrm_reject_fwd_resp(bp, vf_id, fwd_cmd, req_len);
	return;
}

/* For the default completion ring only */
int bnxt_alloc_def_cp_ring(struct bnxt *bp)
{
	struct bnxt_cp_ring_info *cpr = bp->def_cp_ring;
	struct bnxt_ring *cp_ring = cpr->cp_ring_struct;
	int rc;

	rc = bnxt_hwrm_ring_alloc(bp, cp_ring,
				  HWRM_RING_ALLOC_INPUT_RING_TYPE_CMPL,
				  0, HWRM_NA_SIGNATURE);
	if (rc)
		goto err_out;
	cpr->cp_doorbell = bp->pdev->mem_resource[2].addr;
	B_CP_DIS_DB(cpr, cpr->cp_raw_cons);
	bp->grp_info[0].cp_fw_ring_id = cp_ring->fw_ring_id;

err_out:
	return rc;
}

void bnxt_free_def_cp_ring(struct bnxt *bp)
{
	struct bnxt_cp_ring_info *cpr = bp->def_cp_ring;

	if (cpr == NULL)
		return;

	bnxt_free_ring(cpr->cp_ring_struct);
	rte_free(cpr->cp_ring_struct);
	rte_free(cpr);
}

/* For the default completion ring only */
int bnxt_init_def_ring_struct(struct bnxt *bp, unsigned int socket_id)
{
	struct bnxt_cp_ring_info *cpr;
	struct bnxt_ring *ring;

	cpr = rte_zmalloc_socket("cpr",
				 sizeof(struct bnxt_cp_ring_info),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (cpr == NULL)
		return -ENOMEM;
	bp->def_cp_ring = cpr;

	ring = rte_zmalloc_socket("bnxt_cp_ring_struct",
				  sizeof(struct bnxt_ring),
				  RTE_CACHE_LINE_SIZE, socket_id);
	if (ring == NULL)
		return -ENOMEM;
	cpr->cp_ring_struct = ring;
	ring->bd = (void *)cpr->cp_desc_ring;
	ring->bd_dma = cpr->cp_desc_mapping;
	ring->ring_size = rte_align32pow2(DEFAULT_CP_RING_SIZE);
	ring->ring_mask = ring->ring_size - 1;
	ring->vmem_size = 0;
	ring->vmem = NULL;

	return 0;
}
