/* packet-xip.c
 * Routines for XIP dissection
 * Copyright 2012, Cody Doucette <doucette@bu.edu>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <ipproto.h>
#include "packet-xip-dag.h"
#include "packet-xip-dag-userland.h"

/* Minimum XIP header length. */
#define XIPH_MIN_LEN	36

/* Size of a DAG node. */
#define NODE_SIZE	28

/* XIP Ethertype. */
#define ETHERTYPE_XIP	0xC0DE     /* eXpressive Internet Protocol */
				/* [NOT AN OFFICIALLY REGISTERED ID] */

/* Offsets of fields within an XIP header. */
#define XIPH_VERS	0
#define XIPH_NXTH	1
#define XIPH_PLEN	2
#define XIPH_HOPL	4
#define XIPH_NDST	5
#define XIPH_NSRC	6
#define XIPH_LSTN	7
#define XIPH_DSTD	8

static int proto_xip = -1;

static int hf_xip_version = -1;
static int hf_xip_next_hdr = -1;
static int hf_xip_payload_len = -1;
static int hf_xip_hop_limit = -1;
static int hf_xip_num_dst = -1;
static int hf_xip_num_src = -1;
static int hf_xip_last_node = -1;
static int hf_xip_dst_dag = -1;
static int hf_xip_dst_dag_entry = -1;
static int hf_xip_src_dag = -1;
static int hf_xip_src_dag_entry = -1;

static gint ett_xip = -1;
static gint ett_xip_ddag = -1;
static gint ett_xip_sdag = -1;

static dissector_handle_t udp_handle;

static void
display_dag(proto_tree *tr, int hf, tvbuff_t *tvb, guint8 off, char *buf)
{
	guint8 i = 0;
	char *p =  strtok(buf, "\n");

	while (p != NULL) {
		proto_tree_add_string_format(tr, hf, tvb, off + (i * NODE_SIZE),
							NODE_SIZE, p, "%s", p);
		p = strtok(NULL, "\n");
		i++;
	}
}

static int
dissect_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct xia_addr dst;
	struct xia_addr src;

	char dst_string[XIA_MAX_STRADDR_SIZE];
	char src_string[XIA_MAX_STRADDR_SIZE];

	proto_tree *xip_tree = NULL;
	proto_tree *dst_tree = NULL;
	proto_tree *src_tree = NULL;

	proto_item *ti = NULL;

	tvbuff_t *next_tvb;

	guint8 dst_nodes = tvb_get_guint8(tvb, XIPH_NDST);
	guint8 src_nodes = tvb_get_guint8(tvb, XIPH_NSRC);
	guint8 src_offset = XIPH_DSTD + (NODE_SIZE * dst_nodes);
	guint32 hlen = 8 + (NODE_SIZE * dst_nodes) + (NODE_SIZE * src_nodes);
	guint16 plen = tvb_get_ntohs(tvb, XIPH_PLEN);

	memset(&dst, 0, sizeof dst);
	memset(&src, 0, sizeof src);

	if (hlen < XIPH_MIN_LEN) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
		   "Bad XIP header length (%u, should be at least %u)",
		    hlen, XIPH_MIN_LEN);

		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XIP");
	col_set_str(pinfo->cinfo, COL_INFO, "XIP Request");

	if (tree) {

		/* Construct protocol tree. */
		ti = proto_tree_add_item(tree, proto_xip, tvb, 0, hlen, ENC_NA);

		xip_tree = proto_item_add_subtree(ti, ett_xip);

		/* Add header fields to tree. */
		proto_tree_add_item(xip_tree, hf_xip_version, tvb,
		 XIPH_VERS, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_next_hdr, tvb,
		 XIPH_NXTH, 1, ENC_BIG_ENDIAN);

		proto_tree_add_uint_format(xip_tree, hf_xip_payload_len,
 		 tvb, XIPH_PLEN, 2, plen, "Payload Length: %u bytes", plen);

		proto_tree_add_item(xip_tree, hf_xip_hop_limit, tvb,
		 XIPH_HOPL, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_num_dst, tvb,
		 XIPH_NDST, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_num_src, tvb,
		 XIPH_NSRC, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_last_node, tvb,
		 XIPH_LSTN, 1, ENC_BIG_ENDIAN);

		/* Construct Destination DAG subtree. */
		ti = proto_tree_add_item(xip_tree, hf_xip_dst_dag,
		 tvb, XIPH_DSTD, dst_nodes * NODE_SIZE, ENC_BIG_ENDIAN);

		dst_tree = proto_item_add_subtree(ti, ett_xip_ddag);

		tvb_memcpy(tvb, (guint8 *)(&dst), XIPH_DSTD,
		 NODE_SIZE * dst_nodes);

		xia_ntop(&dst, dst_string, XIA_MAX_STRADDR_SIZE, 1);

		display_dag(dst_tree, hf_xip_dst_dag_entry, tvb,
		 XIPH_DSTD, dst_string);

		/* Construct Source DAG subtree. */
		ti = proto_tree_add_item(xip_tree, hf_xip_src_dag, tvb,
		 src_offset, src_nodes * NODE_SIZE, ENC_BIG_ENDIAN);

		src_tree = proto_item_add_subtree(ti, ett_xip_sdag);

		tvb_memcpy(tvb, (guint8 *)(&src), src_offset,
		 NODE_SIZE * src_nodes);

		xia_ntop(&src, src_string, XIA_MAX_STRADDR_SIZE, 1);

		display_dag(src_tree, hf_xip_src_dag_entry, tvb,
		 src_offset, src_string);
	}

	next_tvb = tvb_new_subset(tvb, hlen, -1, -1);
	call_dissector(udp_handle, next_tvb, pinfo, tree);

	return tvb_length(tvb);
}

void
proto_register_xip(void)
{

	static hf_register_info hf[] = {

		{ &hf_xip_version,
		{ "Version", "xip.version", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_next_hdr,
		{ "Next Header", "xip.next_hdr", FT_UINT8,
		   BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext),
		   0x0, NULL, HFILL }},

		{ &hf_xip_payload_len,
		{ "Payload Length", "xip.payload_len", FT_UINT16,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_hop_limit,
		{ "Hop Limit", "xip.hop_limit", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_num_dst,
		{ "Number of Destination Nodes", "xip.num_dst", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_num_src,
		{ "Number of Source Nodes", "xip_num_src", FT_UINT8,
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_last_node,
		{ "Last Node", "xip.last_node", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_dst_dag,
		{ "Destination DAG", "xip.dst_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_dst_dag_entry,
		{ "Destination DAG Entry", "xip.dst_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag,
		{ "Source DAG", "xip.src_dag", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_src_dag_entry,
		{ "Source DAG Entry", "xip.src_dag_entry", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_xip,
		&ett_xip_ddag,
		&ett_xip_sdag
	};


	proto_xip = proto_register_protocol(
		"eXpressive Internet Protocol",
		"XIP",
	        "xip");

	proto_register_field_array(proto_xip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_xip(void)
{
	dissector_handle_t xip_handle;
	xip_handle = new_create_dissector_handle(dissect_xip, proto_xip);
	dissector_add_uint("ethertype", ETHERTYPE_XIP, xip_handle);

	udp_handle = find_dissector("udp");
}
