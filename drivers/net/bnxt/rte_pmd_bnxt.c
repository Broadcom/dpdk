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

#include <inttypes.h>
#include <stdbool.h>

#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>

#include "bnxt.h"
#include "bnxt_filter.h"
#include "bnxt_hwrm.h"
#include "bnxt_vnic.h"
#include "rte_pmd_bnxt.h"
#include "hsi_struct_def_dpdk.h"

static bool _rte_callback_process(struct bnxt* bp,
		struct rte_pmd_bnxt_mb_event_param* cb_param)
{
	_rte_eth_dev_callback_process(bp->eth_dev, RTE_ETH_EVENT_VF_MBOX,
			cb_param);

	RTE_LOG(DEBUG, PMD, "VF %d message type 0x%x handled, result: %d.\n",
			cb_param->vf_id, cb_param->msg_type, cb_param->retval);

	/* Default to approve */
	if (cb_param->retval == RTE_PMD_BNXT_MB_EVENT_PROCEED)
		cb_param->retval = RTE_PMD_BNXT_MB_EVENT_NOOP_ACK;

	return cb_param->retval == RTE_PMD_BNXT_MB_EVENT_NOOP_ACK ? true : false;
}

int bnxt_rcv_msg_from_vf(struct bnxt *bp, uint16_t vf_id, uint16_t type,
					void *msg)
{
	struct rte_pmd_bnxt_mb_event_param cb_param;
	uint32_t msg_buf[16];
	struct hwrm_func_cfg_input *cfg;

	cb_param.retval = RTE_PMD_BNXT_MB_EVENT_PROCEED;
	cb_param.vf_id = vf_id;
	cb_param.msg = msg_buf;

	switch(type) {
	case HWRM_FUNC_CFG:
		cfg = (struct hwrm_func_cfg_input *)msg;
		if (cfg->enables | rte_cpu_to_le_32(HWRM_FUNC_CFG_INPUT_ENABLES_DFLT_MAC_ADDR)) {
			cb_param.msg_type = BNXT_VF_SET_MAC_ADDR;
			memcpy(&msg_buf[1], cfg->dflt_mac_addr, sizeof(cfg->dflt_mac_addr));
			if (_rte_callback_process(bp, &cb_param) == false)
				return false;
		}
		if (cfg->enables | rte_cpu_to_le_32(HWRM_FUNC_CFG_INPUT_ENABLES_DFLT_VLAN)) {
			cb_param.msg_type = BNXT_VF_SET_VLAN;
			msg_buf[1] = cfg->dflt_vlan;
			if (_rte_callback_process(bp, &cb_param) == false)
				return false;
		}
		if (cfg->enables | rte_cpu_to_le_32(HWRM_FUNC_CFG_INPUT_ENABLES_MTU)) {
			cb_param.msg_type = BNXT_VF_SET_MTU;
			msg_buf[1] = cfg->mtu;
			if (_rte_callback_process(bp, &cb_param) == false)
				return false;
		}
		if (cfg->enables | rte_cpu_to_le_32(HWRM_FUNC_CFG_INPUT_ENABLES_MRU)) {
			cb_param.msg_type = BNXT_VF_SET_MRU;
			msg_buf[1] = cfg->mru;
			if (_rte_callback_process(bp, &cb_param) == false)
				return false;
		}
		return true;
		break;
	case HWRM_FUNC_RESET:
		cb_param.msg_type = BNXT_VF_RESET;
		break;
	default:
		/* Default pass undefined hwrm message */
		RTE_LOG(DEBUG, PMD, "VF %d hwrm message 0x%x default passed.\n",
				vf_id, type);
		return true;
	}

	return _rte_callback_process(bp, &cb_param);
}

