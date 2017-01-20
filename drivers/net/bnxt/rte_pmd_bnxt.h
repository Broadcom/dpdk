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

#ifndef _PMD_BNXT_H_
#define _PMD_BNXT_H_

#include <rte_ethdev.h>

/**
 * Response sent back to bnxt driver from user app after callback
 */
enum rte_pmd_bnxt_mb_event_rsp {
	RTE_PMD_BNXT_MB_EVENT_NOOP_ACK,  /**< skip mbox request and ACK */
	RTE_PMD_BNXT_MB_EVENT_NOOP_NACK, /**< skip mbox request and NACK */
	RTE_PMD_BNXT_MB_EVENT_PROCEED,  /**< proceed with mbox request  */
	RTE_PMD_BNXT_MB_EVENT_MAX       /**< max value of this enum */
};

/* mailbox message types */
#define HWRM_FUNC_RESET			(UINT32_C(0x11))
/* TODO expose more */

/**
 * Data sent to the user application when the callback is executed.
 */
struct rte_pmd_bnxt_mb_event_param {
	uint16_t vf_id;     /**< Virtual Function number */
	uint16_t msg_type; /**< VF to PF message type, defined in ixgbe_mbx.h */
	int16_t  retval;   /**< return value */
	void 	*msg;      /**< pointer to message */
};

#endif /* _PMD_BNXT_H_ */
