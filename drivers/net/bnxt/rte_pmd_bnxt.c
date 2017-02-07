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

int rte_pmd_bnxt_set_tx_loopback(uint8_t port, uint8_t on)
{
	struct rte_eth_dev 	*eth_dev;
	struct bnxt 		*bp;
	int 				rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	if (on > 1)
		return -EINVAL;

	eth_dev = &rte_eth_devices[port];
	bp = (struct bnxt *)eth_dev->data->dev_private;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set PF loopback on non-PF port %d!\n",
				port);
		return -ENOTSUP;
	}

	if (on)
		bp->pf.evb_mode = BNXT_EVB_MODE_VEB;
	else
		bp->pf.evb_mode = BNXT_EVB_MODE_VEPA;

	rc = bnxt_hwrm_pf_evb_mode(bp);

	return rc;
}

static void
rte_pmd_bnxt_set_all_queues_drop_en_cb(struct bnxt_vnic_info *vnic, void *onptr)
{
	uint8_t *on = onptr;
	vnic->bd_stall = !(*on);
}

int rte_pmd_bnxt_set_all_queues_drop_en(uint8_t port, uint8_t on)
{
	struct rte_eth_dev *eth_dev;
	struct bnxt *bp;
	uint32_t i;
	int rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	if (on > 1)
		return -EINVAL;

	eth_dev = &rte_eth_devices[port];
	bp = (struct bnxt *)eth_dev->data->dev_private;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set all queues drop on non-PF port!\n");
		return -ENOTSUP;
	}

	if (bp->vnic_info == NULL)
		return -ENODEV;

	/* Stall PF */
	for (i = 0; i < bp->nr_vnics; i++) {
		bp->vnic_info[i].bd_stall = !on;
		rc = bnxt_hwrm_vnic_cfg(bp, &bp->vnic_info[i]);
		if (rc) {
			RTE_LOG(ERR, PMD, "Failed to update PF VNIC %d.\n", i);
			return rc;
		}
	}

	/* Stall all active VFs */
	for (i = 0; i < bp->pf.active_vfs; i++) {
		rc = bnxt_hwrm_func_vf_vnic_cfg_do(bp, i, rte_pmd_bnxt_set_all_queues_drop_en_cb, &on);
		if (rc) {
			RTE_LOG(ERR, PMD, "Failed to update VF VNIC %d.\n", i);
			break;
		}
	}

	return rc;
}

int
rte_pmd_bnxt_set_vf_mac_addr(uint8_t port, uint16_t vf,
		struct ether_addr *mac_addr)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;
	int rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf >= dev_info.max_vfs || mac_addr == NULL)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set VF %d mac address on non-PF port %d!\n",
				vf, port);
		return -ENOTSUP;
	}

	rc = bnxt_hwrm_func_vf_mac(bp, vf, (uint8_t *)mac_addr);

	return rc;
}

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
		RTE_LOG(DEBUG, PMD, "VF %d hwrm message 0x%04x default passed.\n",
				vf_id, type);
		return true;
	}

	return _rte_callback_process(bp, &cb_param);
}

int rte_pmd_bnxt_set_vf_mac_anti_spoof(uint8_t port, uint16_t vf, uint8_t on)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_dev *dev;
	uint32_t func_flags;
	struct bnxt *bp;
	int rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	if (on > 1)
		return -EINVAL;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set mac spoof on non-PF port %d!\n",
				port);
		return -EINVAL;
	}

	if (vf >= dev_info.max_vfs)
		return -EINVAL;

	if (on > 1)	
		return -EINVAL;

	/* Prev setting same as new setting. */
	if (on == bp->pf.vf_info[vf].mac_spoof_en)
		return 0;

	func_flags = bp->pf.vf_info[vf].func_cfg_flags;

	if (on)
		func_flags |= HWRM_FUNC_CFG_INPUT_FLAGS_SRC_MAC_ADDR_CHECK;
	else
		func_flags &= ~HWRM_FUNC_CFG_INPUT_FLAGS_SRC_MAC_ADDR_CHECK;

	bp->pf.vf_info[vf].func_cfg_flags = func_flags;

	rc = bnxt_hwrm_func_cfg_vf_set_flags(bp, vf);
	if (!rc) {
		bp->pf.vf_info[vf].mac_spoof_en = on;
	}

	return rc;
}

static void
rte_pmd_bnxt_set_vf_vlan_stripq_cb(struct bnxt_vnic_info *vnic, void *onptr)
{
	uint8_t *on = onptr;
	vnic->vlan_strip = *on;
}

int
rte_pmd_bnxt_set_vf_vlan_stripq(uint8_t port, uint16_t vf, uint8_t on)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;
	int rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set VF %d stripq on non-PF port %d!\n",
				vf, port);
		return -ENOTSUP;
	}

	rc = bnxt_hwrm_func_vf_vnic_cfg_do(bp, vf, rte_pmd_bnxt_set_vf_vlan_stripq_cb, &on);
	if (rc) {
		RTE_LOG(ERR, PMD, "Failed to update VF VNIC %d.\n", vf);
	}

	return rc;
}

int
rte_pmd_bnxt_set_vf_vlan_insert(uint8_t port, uint16_t vf,
		uint16_t vlan_id)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to set VF %d vlan insert on non-PF port %d!\n",
				vf, port);
		return -ENOTSUP;
	}

	if (vlan_id != bp->pf.vf_info[vf].dflt_vlan)
		return -ENOTSUP;

	return 0;
}
