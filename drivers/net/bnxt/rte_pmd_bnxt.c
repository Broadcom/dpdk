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

#include "bnxt.h"
#include "bnxt_filter.h"
#include "bnxt_hwrm.h"
#include "bnxt_vnic.h"
#include "rte_pmd_bnxt.h"

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
		RTE_LOG(ERR, PMD, "Attempt to operate on none-PF!\n");
		return -ENOTSUP;
	}

	if (on)
		bp->pf.evb_mode = BNXT_EVB_MODE_VEB;
	else
		bp->pf.evb_mode = BNXT_EVB_MODE_VEPA;

	rc = bnxt_hwrm_pf_evb_mode(bp);

	return rc;
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
		RTE_LOG(ERR, PMD, "Attempt to set all queues drop on none-PF port!\n");
		return -ENOTSUP;
	}

	if (bp->vnic_info == NULL)
		return -ENODEV;

	/* Stall PF */
	for (i = 0; i < bp->nr_vnics; i++) {
		bp->vnic_info[i].bd_stall = on;
		rc = bnxt_hwrm_vnic_cfg(bp, &bp->vnic_info[i]);
		if (rc) {
			RTE_LOG(ERR, PMD, "Failed to update PF VNIC %d.\n", i);
			return rc;
		}
	}

	/* Stall all active VFs */
	for (i = 0; i < bp->pf.active_vfs; i++) {
		rc = bnxt_hwrm_func_vf_stall(bp, i, on);
		if (rc) {
			RTE_LOG(ERR, PMD, "Failed to update VF VNIC %d.\n", i);
			break;
		}
	}

	return rc;
}
