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

#include <rte_byteorder.h>

#include "bnxt.h"
#include "bnxt_cpr.h"
#include "bnxt_hwrm.h"
#include "bnxt_rxq.h"
#include "bnxt_stats.h"
#include "bnxt_txq.h"
#include "hsi_struct_def_dpdk.h"

/*
 * Statistics functions
 */

void bnxt_free_stats(struct bnxt *bp)
{
	int i;

	for (i = 0; i < (int)bp->tx_cp_nr_rings; i++) {
		struct bnxt_tx_queue *txq = bp->tx_queues[i];

		bnxt_free_txq_stats(txq);
	}
	for (i = 0; i < (int)bp->rx_cp_nr_rings; i++) {
		struct bnxt_rx_queue *rxq = bp->rx_queues[i];

		bnxt_free_rxq_stats(rxq);
	}
}

void bnxt_stats_get_op(struct rte_eth_dev *eth_dev,
			   struct rte_eth_stats *bnxt_stats)
{
	unsigned int i;
	struct bnxt *bp = eth_dev->data->dev_private;

	memset(bnxt_stats, 0, sizeof(*bnxt_stats));

	for (i = 0; i < bp->rx_cp_nr_rings; i++) {
		struct bnxt_rx_queue *rxq = bp->rx_queues[i];
		struct bnxt_cp_ring_info *cpr = rxq->cp_ring;

		bnxt_hwrm_ctx_qstats(bp, cpr->hw_stats_ctx_id, i, bnxt_stats);
	}

	for (i = 0; i < bp->tx_cp_nr_rings; i++) {
		struct bnxt_tx_queue *txq = bp->tx_queues[i];
		struct bnxt_cp_ring_info *cpr = txq->cp_ring;

		bnxt_hwrm_ctx_qstats(bp, cpr->hw_stats_ctx_id, i, bnxt_stats);
	}
	bnxt_hwrm_func_qstats(bp, 0xffff, bnxt_stats);
	bnxt_stats->rx_nombuf = rte_atomic64_read(&bp->rx_mbuf_alloc_fail);
}

void bnxt_stats_reset_op(struct rte_eth_dev *eth_dev)
{
	struct bnxt *bp = (struct bnxt *)eth_dev->data->dev_private;

	bnxt_clear_all_hwrm_stat_ctxs(bp);
	rte_atomic64_clear(&bp->rx_mbuf_alloc_fail);
}
