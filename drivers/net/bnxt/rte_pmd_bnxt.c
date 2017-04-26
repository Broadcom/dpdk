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
#include <unistd.h>

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
		rc = bnxt_hwrm_func_vf_vnic_query_and_config(bp, i,
				rte_pmd_bnxt_set_all_queues_drop_en_cb, &on,
				bnxt_hwrm_vnic_cfg);
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

int bnxt_rcv_msg_from_vf(struct bnxt *bp, uint16_t vf_id, void *msg)
{
	struct rte_pmd_bnxt_mb_event_param cb_param;

	cb_param.retval = RTE_PMD_BNXT_MB_EVENT_PROCEED;
	cb_param.vf_id = vf_id;
	cb_param.msg = msg;

	_rte_eth_dev_callback_process(bp->eth_dev, RTE_ETH_EVENT_VF_MBOX,
			&cb_param);

	/* Default to approve */
	if (cb_param.retval == RTE_PMD_BNXT_MB_EVENT_PROCEED)
		cb_param.retval = RTE_PMD_BNXT_MB_EVENT_NOOP_ACK;

	return cb_param.retval == RTE_PMD_BNXT_MB_EVENT_NOOP_ACK ? true : false;
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
		func_flags |=
			HWRM_FUNC_CFG_INPUT_FLAGS_SRC_MAC_ADDR_CHECK_ENABLE;
	else
		func_flags |=
			HWRM_FUNC_CFG_INPUT_FLAGS_SRC_MAC_ADDR_CHECK_DISABLE;

	bp->pf.vf_info[vf].func_cfg_flags = func_flags;

	rc = bnxt_hwrm_func_cfg_vf_set_flags(bp, vf);
	if (!rc) {
		bp->pf.vf_info[vf].mac_spoof_en = on;
	}

	return rc;
}

int rte_pmd_bnxt_set_vf_vlan_anti_spoof(uint8_t port, uint16_t vf, uint8_t on)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_dev *dev;
	struct bnxt *bp;
	int rc;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	if (on > 1)
		return -EINVAL;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD,
			"Attempt to set mac spoof on non-PF port %d!\n", port);
		return -EINVAL;
	}

	if (vf >= dev_info.max_vfs)
		return -EINVAL;

	if (on > 1)
		return -EINVAL;

	/* Prev setting same as new setting. */
	if (on == bp->pf.vf_info[vf].vlan_spoof_en)
		return 0;

	if (!bp->pf.vf_info[vf].dflt_vlan) {
		RTE_LOG(ERR, PMD, "Default VLAN not set.\n");
		return -ENOTSUP;
	}

	rc = bnxt_hwrm_func_cfg_vf_set_vlan_anti_spoof(bp, vf);
	if (!rc)
		bp->pf.vf_info[vf].vlan_spoof_en = on;
	else
		RTE_LOG(ERR, PMD, "Failed to update VF VNIC %d.\n", vf);

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

	rc = bnxt_hwrm_func_vf_vnic_query_and_config(bp, vf,
				rte_pmd_bnxt_set_vf_vlan_stripq_cb, &on,
				bnxt_hwrm_vnic_cfg);
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
	int rc;

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

	bp->pf.vf_info[vf].dflt_vlan = vlan_id;
	if (bnxt_hwrm_func_qcfg_current_vf_vlan(bp, vf) == bp->pf.vf_info[vf].dflt_vlan)
		return 0;

	rc = bnxt_hwrm_set_vf_vlan(bp, vf);

	return rc;
}

int rte_pmd_bnxt_get_vf_stats(uint8_t port,
			      uint16_t vf_id,
			      struct rte_eth_stats *stats)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf_id >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to get VF %d stats on non-PF port %d!\n",
				vf_id, port);
		return -ENOTSUP;
	}

	return bnxt_hwrm_func_qstats(bp, bp->pf.first_vf_id + vf_id, stats);
}

int rte_pmd_bnxt_reset_vf_stats(uint8_t port,
				uint16_t vf_id)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf_id >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to reset VF %d stats on non-PF port %d!\n",
				vf_id, port);
		return -ENOTSUP;
	}

	return bnxt_hwrm_func_clr_stats(bp, bp->pf.first_vf_id + vf_id);
}

int rte_pmd_bnxt_get_vf_rx_status(uint8_t port, uint16_t vf_id)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf_id >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to query VF %d RX stats on non-PF port %d!\n",
				vf_id, port);
		return -ENOTSUP;
	}

	return bnxt_vf_default_vnic_count(bp, vf_id);
}

int rte_pmd_bnxt_get_tx_drop_count(uint8_t port, uint64_t *count)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	return bnxt_hwrm_func_qstats_tx_drop(bp, 0xffff, count);
}

int rte_pmd_bnxt_get_vf_tx_drop_count(uint8_t port, uint16_t vf_id, uint64_t *count)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf_id >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD, "Attempt to query VF %d TX drops on non-PF port %d!\n",
				vf_id, port);
		return -ENOTSUP;
	}

	return bnxt_hwrm_func_qstats_tx_drop(bp, bp->pf.first_vf_id + vf_id, count);
}


int rte_pmd_bnxt_mac_addr_add(uint8_t port, struct ether_addr *addr,
				uint32_t vf_id)
{
	struct rte_eth_dev *dev;
	struct rte_eth_dev_info dev_info;
	struct bnxt *bp;
	struct bnxt_filter_info *filter;
	struct bnxt_vnic_info vnic;
	int rc;

	dev = &rte_eth_devices[port];
	rte_eth_dev_info_get(port, &dev_info);
	bp = (struct bnxt *)dev->data->dev_private;

	if (vf_id >= dev_info.max_vfs)
		return -EINVAL;

	if (!BNXT_PF(bp)) {
		RTE_LOG(ERR, PMD,
			"Attempt to config VF %d MAC on non-PF port %d!\n",
			vf_id, port);
		return -ENOTSUP;
	}

	/* If the VF currently uses a random MAC, update default to this one */
	if (bp->pf.vf_info[vf_id].random_mac) {
		if (rte_pmd_bnxt_get_vf_rx_status(port, vf_id) <= 0) {
			rc = bnxt_hwrm_func_vf_mac(bp, vf_id, (uint8_t *)addr);
		}
	}

	/* query the default VNIC id used by the function */
	rc = bnxt_hwrm_func_qcfg_vf_dflt_vnic_id(bp, vf_id);
	if (rc < 0)
		goto exit;

	memset(&vnic, 0, sizeof(struct bnxt_vnic_info));
	vnic.fw_vnic_id = rte_le_to_cpu_16(rc);
	rc = bnxt_hwrm_vnic_qcfg(bp, &vnic, bp->pf.first_vf_id + vf_id);
	if (rc < 0)
		goto exit;

	STAILQ_FOREACH(filter, &bp->pf.vf_info[vf_id].filter, next) {
		if (filter->flags == HWRM_CFA_L2_FILTER_ALLOC_INPUT_FLAGS_PATH_RX
		    && filter->enables == (HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR
		        | HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR_MASK)
		    && memcmp(addr, filter->l2_addr, ETHER_ADDR_LEN) == 0) {
			bnxt_hwrm_clear_filter(bp, filter);
			break;
		}
	}

	if (filter == NULL) {
		filter = bnxt_alloc_vf_filter(bp, vf_id);
	}

	filter->fw_l2_filter_id = UINT64_MAX;
	filter->flags = HWRM_CFA_L2_FILTER_ALLOC_INPUT_FLAGS_PATH_RX;
	filter->enables = HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR |
			HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR_MASK;
	memcpy(filter->l2_addr, addr, ETHER_ADDR_LEN);
	memset(filter->l2_addr_mask, 0xff, ETHER_ADDR_LEN);
	rc = bnxt_hwrm_set_filter(bp, vnic.fw_vnic_id, filter);

exit:
	return rc;
}
