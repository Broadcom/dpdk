/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2018 Broadcom
 * All rights reserved.
 */

#include <sys/queue.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include "bnxt.h"
#include "bnxt_filter.h"
#include "bnxt_hwrm.h"
#include "bnxt_vnic.h"
#include "hsi_struct_def_dpdk.h"

/*
 * Filter Functions
 */

struct bnxt_filter_info *bnxt_alloc_filter(struct bnxt *bp)
{
	struct bnxt_filter_info *filter;

	/* Find the 1st unused filter from the free_filter_list pool*/
	filter = STAILQ_FIRST(&bp->free_filter_list);
	if (!filter) {
		PMD_DRV_LOG(ERR, "No more free filter resources\n");
		return NULL;
	}
	STAILQ_REMOVE_HEAD(&bp->free_filter_list, next);

	/* Default to L2 MAC Addr filter */
	filter->flags = HWRM_CFA_L2_FILTER_ALLOC_INPUT_FLAGS_PATH_RX;
	filter->enables = HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR |
			HWRM_CFA_L2_FILTER_ALLOC_INPUT_ENABLES_L2_ADDR_MASK;
	memcpy(filter->l2_addr, bp->eth_dev->data->mac_addrs->addr_bytes,
	       ETHER_ADDR_LEN);
	memset(filter->l2_addr_mask, 0xff, ETHER_ADDR_LEN);
	return filter;
}

struct bnxt_filter_info *bnxt_alloc_vf_filter(struct bnxt *bp, uint16_t vf)
{
	struct bnxt_filter_info *filter;

	filter = rte_zmalloc("bnxt_vf_filter_info", sizeof(*filter), 0);
	if (!filter) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for VF %hu filters\n",
			vf);
		return NULL;
	}

	filter->fw_l2_filter_id = UINT64_MAX;
	STAILQ_INSERT_TAIL(&bp->pf.vf_info[vf].filter, filter, next);
	return filter;
}

void bnxt_init_filters(struct bnxt *bp)
{
	struct bnxt_filter_info *filter;
	int i, max_filters;

	max_filters = bp->max_l2_ctx;
	STAILQ_INIT(&bp->free_filter_list);
	for (i = 0; i < max_filters; i++) {
		filter = &bp->filter_info[i];
		filter->fw_l2_filter_id = BNXT_NA_SIGNATURE_UINT64;
		filter->fw_em_filter_id = BNXT_NA_SIGNATURE_UINT64;
		filter->fw_ntuple_filter_id = BNXT_NA_SIGNATURE_UINT64;
		STAILQ_INSERT_TAIL(&bp->free_filter_list, filter, next);
	}
}

void bnxt_free_all_filters(struct bnxt *bp)
{
	struct bnxt_vnic_info *vnic;
	struct bnxt_filter_info *filter, *temp_filter;
	int i;

	for (i = 0; i < MAX_FF_POOLS; i++) {
		STAILQ_FOREACH(vnic, &bp->ff_pool[i], next) {
			filter = STAILQ_FIRST(&vnic->filter);
			while (filter) {
				temp_filter = STAILQ_NEXT(filter, next);
				STAILQ_REMOVE(&vnic->filter, filter,
					      bnxt_filter_info, next);
				STAILQ_INSERT_TAIL(&bp->free_filter_list,
						   filter, next);
				filter = temp_filter;
			}
			STAILQ_INIT(&vnic->filter);
		}
	}

	for (i = 0; i < bp->pf.max_vfs; i++) {
		STAILQ_FOREACH(filter, &bp->pf.vf_info[i].filter, next) {
			bnxt_hwrm_clear_l2_filter(bp, filter);
		}
	}
}

void bnxt_free_filter_mem(struct bnxt *bp)
{
	struct bnxt_filter_info *filter;
	uint16_t max_filters, i;
	int rc = 0;

	if (bp->filter_info == NULL)
		return;

	/* Ensure that all filters are freed */
	max_filters = bp->max_l2_ctx;
	for (i = 0; i < max_filters; i++) {
		filter = &bp->filter_info[i];
		if (filter->fw_l2_filter_id != BNXT_NA_SIGNATURE_UINT64) {
			PMD_DRV_LOG(ERR, "HWRM filter is not freed??\n");
			/* Call HWRM to try to free filter again */
			rc = bnxt_hwrm_clear_l2_filter(bp, filter);
			if (rc)
				PMD_DRV_LOG(ERR,
					    "HWRM filter not freed rc = %d\n",
					    rc);
		}
		filter->fw_l2_filter_id = UINT64_MAX;
	}
	STAILQ_INIT(&bp->free_filter_list);

	rte_free(bp->filter_info);
	bp->filter_info = NULL;
}

int bnxt_alloc_filter_mem(struct bnxt *bp)
{
	struct bnxt_filter_info *filter_mem;
	uint16_t max_filters, i;

	max_filters = bp->max_l2_ctx;
	/* Allocate memory for VNIC pool and filter pool */
	filter_mem = rte_zmalloc("bnxt_filter_info",
				 max_filters * sizeof(struct bnxt_filter_info),
				 0);
	if (filter_mem == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for %d filters\n",
			max_filters);
		return -ENOMEM;
	}
	bp->filter_info = filter_mem;

	for (i = 0; i < bp->max_l2_ctx; i++)
		filter_mem[i].fw_l2_filter_id = BNXT_NA_SIGNATURE_UINT64;

	return 0;
}

struct bnxt_filter_info *bnxt_get_unused_filter(struct bnxt *bp)
{
	struct bnxt_filter_info *filter;

	/* Find the 1st unused filter from the free_filter_list pool*/
	filter = STAILQ_FIRST(&bp->free_filter_list);
	if (!filter) {
		PMD_DRV_LOG(ERR, "No more free filter resources\n");
		return NULL;
	}
	STAILQ_REMOVE_HEAD(&bp->free_filter_list, next);

	return filter;
}

void bnxt_free_filter(struct bnxt *bp, struct bnxt_filter_info *filter)
{
	STAILQ_INSERT_TAIL(&bp->free_filter_list, filter, next);
}

static struct bnxt_filter_info *
bnxt_match_and_validate_ether_filter(struct bnxt *bp,
				     struct rte_eth_ethertype_filter *efilter,
				     struct bnxt_vnic_info *vnic0,
				     struct bnxt_vnic_info *vnic,
				     int *ret)
{
	struct bnxt_filter_info *mfilter = NULL;
	int match = 0;
	*ret = 0;

	if (efilter->ether_type == ETHER_TYPE_IPv4 ||
	    efilter->ether_type == ETHER_TYPE_IPv6) {
		PMD_DRV_LOG(ERR,
			    "invalid ether_type(0x%04x) in ethertype filter\n",
			    efilter->ether_type);
		*ret = -EINVAL;
		goto exit;
	}
	if (efilter->queue >= bp->rx_nr_rings) {
		PMD_DRV_LOG(ERR, "Invalid queue %d\n", efilter->queue);
		*ret = -EINVAL;
		goto exit;
	}

	vnic0 = STAILQ_FIRST(&bp->ff_pool[0]);
	vnic = STAILQ_FIRST(&bp->ff_pool[efilter->queue]);
	if (vnic == NULL) {
		PMD_DRV_LOG(ERR, "Invalid queue %d\n", efilter->queue);
		*ret = -EINVAL;
		goto exit;
	}

	if (efilter->flags & RTE_ETHTYPE_FLAGS_DROP) {
		STAILQ_FOREACH(mfilter, &vnic0->filter, next) {
			if ((!memcmp(efilter->mac_addr.addr_bytes,
				     mfilter->l2_addr, ETHER_ADDR_LEN) &&
			     mfilter->flags ==
			     HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_FLAGS_DROP &&
			     mfilter->ethertype == efilter->ether_type)) {
				match = 1;
				break;
			}
		}
	} else {
		STAILQ_FOREACH(mfilter, &vnic->filter, next)
			if ((!memcmp(efilter->mac_addr.addr_bytes,
				     mfilter->l2_addr, ETHER_ADDR_LEN) &&
			     mfilter->ethertype == efilter->ether_type &&
			     mfilter->flags ==
			     HWRM_CFA_L2_FILTER_CFG_INPUT_FLAGS_PATH_RX)) {
				match = 1;
				break;
			}
	}

	if (match)
		*ret = -EEXIST;

exit:
	return mfilter;
}

static int
bnxt_ethertype_filter(struct rte_eth_dev *dev,
			enum rte_filter_op filter_op,
			void *arg)
{
	struct bnxt *bp = (struct bnxt *)dev->data->dev_private;
	struct rte_eth_ethertype_filter *efilter =
		(struct rte_eth_ethertype_filter *)arg;
	struct bnxt_filter_info *bfilter, *filter1;
	struct bnxt_vnic_info *vnic, *vnic0;
	int ret;

	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL) {
		PMD_DRV_LOG(ERR,
			    "arg shouldn't be NULL for operation %u\n",
			    filter_op);
		return -EINVAL;
	}

	vnic0 = STAILQ_FIRST(&bp->ff_pool[0]);
	vnic = STAILQ_FIRST(&bp->ff_pool[efilter->queue]);

	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		bnxt_match_and_validate_ether_filter(bp, efilter,
						     vnic0, vnic, &ret);
		if (ret < 0)
			return ret;

		bfilter = bnxt_get_unused_filter(bp);
		if (bfilter == NULL) {
			PMD_DRV_LOG(ERR,
				"Not enough resources for a new filter.\n");
			return -ENOMEM;
		}
		bfilter->filter_type = HWRM_CFA_NTUPLE_FILTER;
		memcpy(bfilter->l2_addr, efilter->mac_addr.addr_bytes,
		       ETHER_ADDR_LEN);
		memcpy(bfilter->dst_macaddr, efilter->mac_addr.addr_bytes,
		       ETHER_ADDR_LEN);
		bfilter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_MACADDR;
		bfilter->ethertype = efilter->ether_type;
		bfilter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;

		filter1 = bnxt_get_l2_filter(bp, bfilter, vnic0);
		if (filter1 == NULL) {
			ret = -1;
			goto cleanup;
		}
		bfilter->enables |=
			HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_ENABLES_L2_FILTER_ID;
		bfilter->fw_l2_filter_id = filter1->fw_l2_filter_id;

		bfilter->dst_id = vnic->fw_vnic_id;

		if (efilter->flags & RTE_ETHTYPE_FLAGS_DROP) {
			bfilter->flags =
				HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_FLAGS_DROP;
		}

		ret = bnxt_hwrm_set_ntuple_filter(bp, bfilter->dst_id, bfilter);
		if (ret)
			goto cleanup;
		STAILQ_INSERT_TAIL(&vnic->filter, bfilter, next);
		break;
	case RTE_ETH_FILTER_DELETE:
		filter1 = bnxt_match_and_validate_ether_filter(bp,
							       efilter,
							       vnic0,
							       vnic,
							       &ret);
		if (ret == -EEXIST) {
			ret = bnxt_hwrm_clear_ntuple_filter(bp, filter1);

			STAILQ_REMOVE(&vnic->filter, filter1, bnxt_filter_info,
				      next);
			bnxt_free_filter(bp, filter1);
		} else if (ret == 0) {
			PMD_DRV_LOG(ERR, "No matching filter found\n");
		}
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported operation %u\n", filter_op);
		ret = -EINVAL;
		goto error;
	}
	return ret;
cleanup:
	bnxt_free_filter(bp, bfilter);
error:
	return ret;
}

static inline int
parse_ntuple_filter(struct bnxt *bp,
		    struct rte_eth_ntuple_filter *nfilter,
		    struct bnxt_filter_info *bfilter)
{
	uint32_t en = 0;

	if (nfilter->queue >= bp->rx_nr_rings) {
		PMD_DRV_LOG(ERR, "Invalid queue %d\n", nfilter->queue);
		return -EINVAL;
	}

	switch (nfilter->dst_port_mask) {
	case UINT16_MAX:
		bfilter->dst_port_mask = -1;
		bfilter->dst_port = nfilter->dst_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT |
			NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT_MASK;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid dst_port mask\n");
		return -EINVAL;
	}

	bfilter->ip_addr_type = NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV4;
	en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;

	switch (nfilter->proto_mask) {
	case UINT8_MAX:
		if (nfilter->proto == 17) /* IPPROTO_UDP */
			bfilter->ip_protocol = 17;
		else if (nfilter->proto == 6) /* IPPROTO_TCP */
			bfilter->ip_protocol = 6;
		else
			return -EINVAL;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid protocol mask\n");
		return -EINVAL;
	}

	switch (nfilter->dst_ip_mask) {
	case UINT32_MAX:
		bfilter->dst_ipaddr_mask[0] = -1;
		bfilter->dst_ipaddr[0] = nfilter->dst_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR |
			NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid dst_ip mask\n");
		return -EINVAL;
	}

	switch (nfilter->src_ip_mask) {
	case UINT32_MAX:
		bfilter->src_ipaddr_mask[0] = -1;
		bfilter->src_ipaddr[0] = nfilter->src_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR |
			NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid src_ip mask\n");
		return -EINVAL;
	}

	switch (nfilter->src_port_mask) {
	case UINT16_MAX:
		bfilter->src_port_mask = -1;
		bfilter->src_port = nfilter->src_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT |
			NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT_MASK;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid src_port mask\n");
		return -EINVAL;
	}

	/* TODO Priority
	 * nfilter->priority = (uint8_t)filter->priority;
	 */

	bfilter->enables = en;
	return 0;
}

static struct bnxt_filter_info*
bnxt_match_ntuple_filter(struct bnxt *bp,
			 struct bnxt_filter_info *bfilter,
			 struct bnxt_vnic_info **mvnic)
{
	struct bnxt_filter_info *mfilter = NULL;
	int i;

	for (i = bp->nr_vnics - 1; i >= 0; i--) {
		struct bnxt_vnic_info *vnic = &bp->vnic_info[i];

		STAILQ_FOREACH(mfilter, &vnic->filter, next) {
			if (bfilter->src_ipaddr[0] == mfilter->src_ipaddr[0] &&
			    bfilter->src_ipaddr_mask[0] ==
			    mfilter->src_ipaddr_mask[0] &&
			    bfilter->src_port == mfilter->src_port &&
			    bfilter->src_port_mask == mfilter->src_port_mask &&
			    bfilter->dst_ipaddr[0] == mfilter->dst_ipaddr[0] &&
			    bfilter->dst_ipaddr_mask[0] ==
			    mfilter->dst_ipaddr_mask[0] &&
			    bfilter->dst_port == mfilter->dst_port &&
			    bfilter->dst_port_mask == mfilter->dst_port_mask &&
			    bfilter->flags == mfilter->flags &&
			    bfilter->enables == mfilter->enables) {
				if (mvnic)
					*mvnic = vnic;
				return mfilter;
			}
		}
	}
	return NULL;
}

static int
bnxt_cfg_ntuple_filter(struct bnxt *bp,
		       struct rte_eth_ntuple_filter *nfilter,
		       enum rte_filter_op filter_op)
{
	struct bnxt_filter_info *bfilter, *mfilter, *filter1;
	struct bnxt_vnic_info *vnic, *vnic0, *mvnic;
	int ret;

	if (nfilter->flags != RTE_5TUPLE_FLAGS) {
		PMD_DRV_LOG(ERR, "only 5tuple is supported\n");
		return -EINVAL;
	}

	if (nfilter->flags & RTE_NTUPLE_FLAGS_TCP_FLAG) {
		PMD_DRV_LOG(ERR, "Ntuple filter: TCP flags not supported\n");
		return -EINVAL;
	}

	bfilter = bnxt_get_unused_filter(bp);
	if (bfilter == NULL) {
		PMD_DRV_LOG(ERR, "Not enough resources for a new filter\n");
		return -ENOMEM;
	}
	ret = parse_ntuple_filter(bp, nfilter, bfilter);
	if (ret < 0)
		goto free_filter;

	vnic = STAILQ_FIRST(&bp->ff_pool[nfilter->queue]);
	vnic0 = STAILQ_FIRST(&bp->ff_pool[0]);
	filter1 = STAILQ_FIRST(&vnic0->filter);
	if (filter1 == NULL) {
		ret = -1;
		goto free_filter;
	}

	bfilter->dst_id = vnic->fw_vnic_id;
	bfilter->fw_l2_filter_id = filter1->fw_l2_filter_id;
	bfilter->enables |=
		HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_ENABLES_L2_FILTER_ID;
	bfilter->ethertype = 0x800;
	bfilter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;

	mfilter = bnxt_match_ntuple_filter(bp, bfilter, &mvnic);

	if (mfilter != NULL && filter_op == RTE_ETH_FILTER_ADD &&
	    bfilter->dst_id == mfilter->dst_id) {
		PMD_DRV_LOG(ERR, "filter exists.\n");
		ret = -EEXIST;
		goto free_filter;
	} else if (mfilter != NULL && filter_op == RTE_ETH_FILTER_ADD &&
		   bfilter->dst_id != mfilter->dst_id) {
		mfilter->dst_id = vnic->fw_vnic_id;
		ret = bnxt_hwrm_set_ntuple_filter(bp, mfilter->dst_id, mfilter);
		STAILQ_REMOVE(&mvnic->filter, mfilter, bnxt_filter_info, next);
		STAILQ_INSERT_TAIL(&vnic->filter, mfilter, next);
		PMD_DRV_LOG(ERR, "filter with matching pattern exists.\n");
		PMD_DRV_LOG(ERR, " Updated it to the new destination queue\n");
		goto free_filter;
	}
	if (mfilter == NULL && filter_op == RTE_ETH_FILTER_DELETE) {
		PMD_DRV_LOG(ERR, "filter doesn't exist\n");
		ret = -ENOENT;
		goto free_filter;
	}

	if (filter_op == RTE_ETH_FILTER_ADD) {
		bfilter->filter_type = HWRM_CFA_NTUPLE_FILTER;
		ret = bnxt_hwrm_set_ntuple_filter(bp, bfilter->dst_id, bfilter);
		if (ret)
			goto free_filter;
		STAILQ_INSERT_TAIL(&vnic->filter, bfilter, next);
	} else {
		if (mfilter == NULL) {
			/* This should not happen. But for Coverity! */
			ret = -ENOENT;
			goto free_filter;
		}
		ret = bnxt_hwrm_clear_ntuple_filter(bp, mfilter);

		STAILQ_REMOVE(&vnic->filter, mfilter, bnxt_filter_info, next);
		bnxt_free_filter(bp, mfilter);
		mfilter->fw_l2_filter_id = -1;
		bnxt_free_filter(bp, bfilter);
		bfilter->fw_l2_filter_id = -1;
	}

	return 0;
free_filter:
	bfilter->fw_l2_filter_id = -1;
	bnxt_free_filter(bp, bfilter);
	return ret;
}

static int
bnxt_ntuple_filter(struct rte_eth_dev *dev,
		   enum rte_filter_op filter_op,
		   void *arg)
{
	struct bnxt *bp = (struct bnxt *)dev->data->dev_private;
	int ret;

	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL) {
		PMD_DRV_LOG(ERR,
			    "arg shouldn't be NULL for operation %u\n",
			    filter_op);
		return -EINVAL;
	}

	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		ret = bnxt_cfg_ntuple_filter
			(bp,
			 (struct rte_eth_ntuple_filter *)arg,
			 filter_op);
		break;
	case RTE_ETH_FILTER_DELETE:
		ret = bnxt_cfg_ntuple_filter
			(bp,
			 (struct rte_eth_ntuple_filter *)arg,
			 filter_op);
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported operation %u\n", filter_op);
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int
bnxt_parse_fdir_filter(struct bnxt *bp,
		       struct rte_eth_fdir_filter *fdir,
		       struct bnxt_filter_info *filter)
{
	enum rte_fdir_mode fdir_mode =
		bp->eth_dev->data->dev_conf.fdir_conf.mode;
	struct bnxt_vnic_info *vnic0, *vnic;
	struct bnxt_filter_info *filter1;
	uint32_t en = 0;
	int i;

	if (fdir_mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
		return -EINVAL;

	filter->l2_ovlan = fdir->input.flow_ext.vlan_tci;
	en |= EM_FLOW_ALLOC_INPUT_EN_OVLAN_VID;

	switch (fdir->input.flow_type) {
	case RTE_ETH_FLOW_IPV4:
	case RTE_ETH_FLOW_NONFRAG_IPV4_OTHER:
		/* FALLTHROUGH */
		filter->src_ipaddr[0] = fdir->input.flow.ip4_flow.src_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		filter->dst_ipaddr[0] = fdir->input.flow.ip4_flow.dst_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		filter->ip_protocol = fdir->input.flow.ip4_flow.proto;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV4;
		filter->src_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->dst_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		filter->ethertype = 0x800;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV4_TCP:
		filter->src_port = fdir->input.flow.tcp4_flow.src_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT;
		filter->dst_port = fdir->input.flow.tcp4_flow.dst_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT;
		filter->dst_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT_MASK;
		filter->src_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT_MASK;
		filter->src_ipaddr[0] = fdir->input.flow.tcp4_flow.ip.src_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		filter->dst_ipaddr[0] = fdir->input.flow.tcp4_flow.ip.dst_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		filter->ip_protocol = 6;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV4;
		filter->src_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->dst_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		filter->ethertype = 0x800;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV4_UDP:
		filter->src_port = fdir->input.flow.udp4_flow.src_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT;
		filter->dst_port = fdir->input.flow.udp4_flow.dst_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT;
		filter->dst_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT_MASK;
		filter->src_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT_MASK;
		filter->src_ipaddr[0] = fdir->input.flow.udp4_flow.ip.src_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		filter->dst_ipaddr[0] = fdir->input.flow.udp4_flow.ip.dst_ip;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		filter->ip_protocol = 17;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV4;
		filter->src_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->dst_ipaddr_mask[0] = 0xffffffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		filter->ethertype = 0x800;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_IPV6:
	case RTE_ETH_FLOW_NONFRAG_IPV6_OTHER:
		/* FALLTHROUGH */
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV6;
		filter->ip_protocol = fdir->input.flow.ipv6_flow.proto;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		rte_memcpy(filter->src_ipaddr,
			   fdir->input.flow.ipv6_flow.src_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		rte_memcpy(filter->dst_ipaddr,
			   fdir->input.flow.ipv6_flow.dst_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		memset(filter->dst_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		memset(filter->src_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->ethertype = 0x86dd;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_TCP:
		filter->src_port = fdir->input.flow.tcp6_flow.src_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT;
		filter->dst_port = fdir->input.flow.tcp6_flow.dst_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT;
		filter->dst_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT_MASK;
		filter->src_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT_MASK;
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV6;
		filter->ip_protocol = fdir->input.flow.tcp6_flow.ip.proto;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		rte_memcpy(filter->src_ipaddr,
			   fdir->input.flow.tcp6_flow.ip.src_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		rte_memcpy(filter->dst_ipaddr,
			   fdir->input.flow.tcp6_flow.ip.dst_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		memset(filter->dst_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		memset(filter->src_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->ethertype = 0x86dd;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_NONFRAG_IPV6_UDP:
		filter->src_port = fdir->input.flow.udp6_flow.src_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT;
		filter->dst_port = fdir->input.flow.udp6_flow.dst_port;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT;
		filter->dst_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_PORT_MASK;
		filter->src_port_mask = 0xffff;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_PORT_MASK;
		filter->ip_addr_type =
			NTUPLE_FLTR_ALLOC_INPUT_IP_ADDR_TYPE_IPV6;
		filter->ip_protocol = fdir->input.flow.udp6_flow.ip.proto;
		en |= NTUPLE_FLTR_ALLOC_IN_EN_IP_PROTO;
		rte_memcpy(filter->src_ipaddr,
			   fdir->input.flow.udp6_flow.ip.src_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR;
		rte_memcpy(filter->dst_ipaddr,
			   fdir->input.flow.udp6_flow.ip.dst_ip, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR;
		memset(filter->dst_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_IPADDR_MASK;
		memset(filter->src_ipaddr_mask, 0xff, 16);
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_SRC_IPADDR_MASK;
		filter->ethertype = 0x86dd;
		filter->enables |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_L2_PAYLOAD:
		filter->ethertype = fdir->input.flow.l2_flow.ether_type;
		en |= NTUPLE_FLTR_ALLOC_INPUT_EN_ETHERTYPE;
		break;
	case RTE_ETH_FLOW_VXLAN:
		if (fdir->action.behavior == RTE_ETH_FDIR_REJECT)
			return -EINVAL;
		filter->vni = fdir->input.flow.tunnel_flow.tunnel_id;
		filter->tunnel_type =
			CFA_NTUPLE_FILTER_ALLOC_REQ_TUNNEL_TYPE_VXLAN;
		en |= HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_ENABLES_TUNNEL_TYPE;
		break;
	case RTE_ETH_FLOW_NVGRE:
		if (fdir->action.behavior == RTE_ETH_FDIR_REJECT)
			return -EINVAL;
		filter->vni = fdir->input.flow.tunnel_flow.tunnel_id;
		filter->tunnel_type =
			CFA_NTUPLE_FILTER_ALLOC_REQ_TUNNEL_TYPE_NVGRE;
		en |= HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_ENABLES_TUNNEL_TYPE;
		break;
	case RTE_ETH_FLOW_UNKNOWN:
	case RTE_ETH_FLOW_RAW:
	case RTE_ETH_FLOW_FRAG_IPV4:
	case RTE_ETH_FLOW_NONFRAG_IPV4_SCTP:
	case RTE_ETH_FLOW_FRAG_IPV6:
	case RTE_ETH_FLOW_NONFRAG_IPV6_SCTP:
	case RTE_ETH_FLOW_IPV6_EX:
	case RTE_ETH_FLOW_IPV6_TCP_EX:
	case RTE_ETH_FLOW_IPV6_UDP_EX:
	case RTE_ETH_FLOW_GENEVE:
		/* FALLTHROUGH */
	default:
		return -EINVAL;
	}

	vnic0 = STAILQ_FIRST(&bp->ff_pool[0]);
	vnic = STAILQ_FIRST(&bp->ff_pool[fdir->action.rx_queue]);
	if (vnic == NULL) {
		PMD_DRV_LOG(ERR, "Invalid queue %d\n", fdir->action.rx_queue);
		return -EINVAL;
	}

	if (fdir_mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		rte_memcpy(filter->dst_macaddr,
			   fdir->input.flow.mac_vlan_flow.mac_addr.addr_bytes,
			   6);
			en |= NTUPLE_FLTR_ALLOC_INPUT_EN_DST_MACADDR;
	}

	if (fdir->action.behavior == RTE_ETH_FDIR_REJECT) {
		filter->flags = HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_FLAGS_DROP;
		filter1 = STAILQ_FIRST(&vnic0->filter);
	} else {
		filter->dst_id = vnic->fw_vnic_id;
		for (i = 0; i < ETHER_ADDR_LEN; i++)
			if (filter->dst_macaddr[i] == 0x00)
				filter1 = STAILQ_FIRST(&vnic0->filter);
			else
				filter1 = bnxt_get_l2_filter(bp, filter, vnic);
	}

	if (filter1 == NULL)
		return -EINVAL;

	en |= HWRM_CFA_NTUPLE_FILTER_ALLOC_INPUT_ENABLES_L2_FILTER_ID;
	filter->fw_l2_filter_id = filter1->fw_l2_filter_id;

	filter->enables = en;

	return 0;
}

static struct bnxt_filter_info *
bnxt_match_fdir(struct bnxt *bp,
		struct bnxt_filter_info *nf,
		struct bnxt_vnic_info **mvnic)
{
	struct bnxt_filter_info *mf = NULL;
	int i;

	for (i = bp->nr_vnics - 1; i >= 0; i--) {
		struct bnxt_vnic_info *vnic = &bp->vnic_info[i];

		STAILQ_FOREACH(mf, &vnic->filter, next) {
			if (mf->filter_type == nf->filter_type &&
			    mf->flags == nf->flags &&
			    mf->src_port == nf->src_port &&
			    mf->src_port_mask == nf->src_port_mask &&
			    mf->dst_port == nf->dst_port &&
			    mf->dst_port_mask == nf->dst_port_mask &&
			    mf->ip_protocol == nf->ip_protocol &&
			    mf->ip_addr_type == nf->ip_addr_type &&
			    mf->ethertype == nf->ethertype &&
			    mf->vni == nf->vni &&
			    mf->tunnel_type == nf->tunnel_type &&
			    mf->l2_ovlan == nf->l2_ovlan &&
			    mf->l2_ovlan_mask == nf->l2_ovlan_mask &&
			    mf->l2_ivlan == nf->l2_ivlan &&
			    mf->l2_ivlan_mask == nf->l2_ivlan_mask &&
			    !memcmp(mf->l2_addr, nf->l2_addr, ETHER_ADDR_LEN) &&
			    !memcmp(mf->l2_addr_mask, nf->l2_addr_mask,
				    ETHER_ADDR_LEN) &&
			    !memcmp(mf->src_macaddr, nf->src_macaddr,
				    ETHER_ADDR_LEN) &&
			    !memcmp(mf->dst_macaddr, nf->dst_macaddr,
				    ETHER_ADDR_LEN) &&
			    !memcmp(mf->src_ipaddr, nf->src_ipaddr,
				    sizeof(nf->src_ipaddr)) &&
			    !memcmp(mf->src_ipaddr_mask, nf->src_ipaddr_mask,
				    sizeof(nf->src_ipaddr_mask)) &&
			    !memcmp(mf->dst_ipaddr, nf->dst_ipaddr,
				    sizeof(nf->dst_ipaddr)) &&
			    !memcmp(mf->dst_ipaddr_mask, nf->dst_ipaddr_mask,
				    sizeof(nf->dst_ipaddr_mask))) {
				if (mvnic)
					*mvnic = vnic;
				return mf;
			}
		}
	}
	return NULL;
}

static int
bnxt_fdir_filter(struct rte_eth_dev *dev,
		 enum rte_filter_op filter_op,
		 void *arg)
{
	struct bnxt *bp = (struct bnxt *)dev->data->dev_private;
	struct rte_eth_fdir_filter *fdir  = (struct rte_eth_fdir_filter *)arg;
	struct bnxt_filter_info *filter, *match;
	struct bnxt_vnic_info *vnic, *mvnic;
	int ret = 0, i;

	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL && filter_op != RTE_ETH_FILTER_FLUSH)
		return -EINVAL;

	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
	case RTE_ETH_FILTER_DELETE:
		/* FALLTHROUGH */
		filter = bnxt_get_unused_filter(bp);
		if (filter == NULL) {
			PMD_DRV_LOG(ERR,
				"Not enough resources for a new flow.\n");
			return -ENOMEM;
		}

		ret = bnxt_parse_fdir_filter(bp, fdir, filter);
		if (ret != 0)
			goto free_filter;
		filter->filter_type = HWRM_CFA_NTUPLE_FILTER;

		if (fdir->action.behavior == RTE_ETH_FDIR_REJECT)
			vnic = STAILQ_FIRST(&bp->ff_pool[0]);
		else
			vnic = STAILQ_FIRST(&bp->ff_pool[fdir->action.rx_queue]);

		match = bnxt_match_fdir(bp, filter, &mvnic);
		if (match != NULL && filter_op == RTE_ETH_FILTER_ADD) {
			if (match->dst_id == vnic->fw_vnic_id) {
				PMD_DRV_LOG(ERR, "Flow already exists.\n");
				ret = -EEXIST;
				goto free_filter;
			} else {
				match->dst_id = vnic->fw_vnic_id;
				ret = bnxt_hwrm_set_ntuple_filter(bp,
								  match->dst_id,
								  match);
				STAILQ_REMOVE(&mvnic->filter, match,
					      bnxt_filter_info, next);
				STAILQ_INSERT_TAIL(&vnic->filter, match, next);
				PMD_DRV_LOG(ERR,
					"Filter with matching pattern exist\n");
				PMD_DRV_LOG(ERR,
					"Updated it to new destination q\n");
				goto free_filter;
			}
		}
		if (match == NULL && filter_op == RTE_ETH_FILTER_DELETE) {
			PMD_DRV_LOG(ERR, "Flow does not exist.\n");
			ret = -ENOENT;
			goto free_filter;
		}

		if (filter_op == RTE_ETH_FILTER_ADD) {
			ret = bnxt_hwrm_set_ntuple_filter(bp,
							  filter->dst_id,
							  filter);
			if (ret)
				goto free_filter;
			STAILQ_INSERT_TAIL(&vnic->filter, filter, next);
		} else {
			ret = bnxt_hwrm_clear_ntuple_filter(bp, match);
			STAILQ_REMOVE(&vnic->filter, match,
				      bnxt_filter_info, next);
			bnxt_free_filter(bp, match);
			filter->fw_l2_filter_id = -1;
			bnxt_free_filter(bp, filter);
		}
		break;
	case RTE_ETH_FILTER_FLUSH:
		for (i = bp->nr_vnics - 1; i >= 0; i--) {
			struct bnxt_vnic_info *vnic = &bp->vnic_info[i];

			STAILQ_FOREACH(filter, &vnic->filter, next) {
				if (filter->filter_type ==
				    HWRM_CFA_NTUPLE_FILTER) {
					ret =
					bnxt_hwrm_clear_ntuple_filter(bp,
								      filter);
					STAILQ_REMOVE(&vnic->filter, filter,
						      bnxt_filter_info, next);
				}
			}
		}
		return ret;
	case RTE_ETH_FILTER_UPDATE:
	case RTE_ETH_FILTER_STATS:
	case RTE_ETH_FILTER_INFO:
		/* FALLTHROUGH */
		PMD_DRV_LOG(ERR, "operation %u not implemented\n", filter_op);
		break;
	default:
		PMD_DRV_LOG(ERR, "unknown operation %u\n", filter_op);
		ret = -EINVAL;
		break;
	}
	return ret;

free_filter:
	filter->fw_l2_filter_id = -1;
	bnxt_free_filter(bp, filter);
	return ret;
}

int
bnxt_filter_ctrl_op(struct rte_eth_dev *dev,
		    enum rte_filter_type filter_type,
		    enum rte_filter_op filter_op,
		    void *arg)
{
	int ret = 0;

	switch (filter_type) {
	case RTE_ETH_FILTER_TUNNEL:
		PMD_DRV_LOG(ERR,
			"Filter type (%d) to be implemented\n", filter_type);
		break;
	case RTE_ETH_FILTER_FDIR:
		ret = bnxt_fdir_filter(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_NTUPLE:
		ret = bnxt_ntuple_filter(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_ETHERTYPE:
		ret = bnxt_ethertype_filter(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_GENERIC:
		if (filter_op != RTE_ETH_FILTER_GET)
			return -EINVAL;
		*(const void **)arg = &bnxt_flow_ops;
		break;
	default:
		PMD_DRV_LOG(ERR,
			"Filter type (%d) not supported\n", filter_type);
		ret = -EINVAL;
		break;
	}
	return ret;
}
