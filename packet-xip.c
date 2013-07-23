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
#include <epan/expert.h>
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

static dissector_handle_t data_handle;

#define XID_TYPE_AD	0x10
#define XID_TYPE_HID	0x11
#define XID_TYPE_CID	0x12
#define XID_TYPE_SID	0x13
#define XID_TYPE_UNITED_4ID	0x14
#define XID_TYPE_4ID	0x15
#define XID_TYPE_U4ID	0x16
#define XID_TYPE_XDP	0x17
#define XID_TYPE_SERVAL	0x18
#define XID_TYPE_FLOWID	0x19

#define XID_LEN		20

static gchar *
type_to_name(guint32 type)
{
	gchar *name;

	switch (type) {
	case XID_TYPE_AD:
		name = "ad";
		break;
	case XID_TYPE_HID:
		name = "hid";
		break;
	case XID_TYPE_CID:
		name = "cid";
		break;
	case XID_TYPE_SID:
		name = "sid";
		break;
	case XID_TYPE_UNITED_4ID:
		name = "united4id";
		break;
	case XID_TYPE_4ID:
		name = "4id";
		break;
	case XID_TYPE_U4ID:
		name = "u4id";
		break;
	case XID_TYPE_XDP:
		name = "xdp";
		break;
	case XID_TYPE_SERVAL:
		name = "serval";
		break;
	case XID_TYPE_FLOWID:
		name = "flowid";
		break;
	default:
		name = "nat";
		break;
	}

	return name;
}


static void
map_types(char *str, char *copy, guint32 type)
{
	char *start, *end, *name = type_to_name(type);
	int len, off = 0;
	start = strchr(str, '-') + 1;
	end = strchr(str, '\0');
	len = end - start;

	if (str[0] == '!') {
		copy[0] = '!';
		off = 1;
	}

	strncpy(copy + off, name, strlen(name));
	strncpy(copy + off + strlen(name), "-", strlen("-"));
	strncpy(copy + off + strlen(name) + strlen("-"), start, len);
	copy[off + strlen(name) + strlen("-") + len] = '\0';
}

static void
display_dag(proto_tree *tr, int hf, tvbuff_t *tvb, guint8 off, char *buf,
	guint8 num_nodes)
{
	guint8 i;
	char *copy;
	char *p =  strtok(buf, "\n");
	guint32 type;

	for (i = 0; i < num_nodes; i++) {
		type = tvb_get_ntohl(tvb, off + (i * NODE_SIZE));
		copy = calloc(strlen(p) + strlen(type_to_name(type)) - 4, 1);
		map_types(p, copy, type);
		proto_tree_add_string_format(tr, hf, tvb,
		 off + (i * NODE_SIZE), NODE_SIZE, copy, "%s", copy);
		p = strtok(NULL, "\n");
		free(copy);
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
	proto_item *pti = NULL;

	tvbuff_t *next_tvb;

	guint8 dst_nodes = tvb_get_guint8(tvb, XIPH_NDST);
	guint8 src_nodes = tvb_get_guint8(tvb, XIPH_NSRC);
	guint8 src_offset = XIPH_DSTD + (NODE_SIZE * dst_nodes);
	guint32 hlen = 8 + (NODE_SIZE * dst_nodes) + (NODE_SIZE * src_nodes);
	guint16 plen = tvb_get_ntohs(tvb, XIPH_PLEN);
	guint8 last_node = tvb_get_guint8(tvb, XIPH_LSTN);
	gchar *format = "";
	guint32 next_diss = tvb_get_ntohl(tvb,
	 XIPH_DSTD + (dst_nodes - 1) * NODE_SIZE);

	memset(&dst, 0, sizeof dst);
	memset(&src, 0, sizeof src);

	if (hlen < XIPH_MIN_LEN) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
		   "Bad XIP header length (%u, should be at least %u)",
		    hlen, XIPH_MIN_LEN);

		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XIP");
	col_set_str(pinfo->cinfo, COL_INFO, "XIP Packet");

	if (tree) {

		/* Construct protocol tree. */
		ti = proto_tree_add_item(tree, proto_xip, tvb, 0, hlen, ENC_NA);

		xip_tree = proto_item_add_subtree(ti, ett_xip);

		/* Add header fields to tree. */
		proto_tree_add_item(xip_tree, hf_xip_version, tvb,
		 XIPH_VERS, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_next_hdr, tvb,
		 XIPH_NXTH, 1, ENC_BIG_ENDIAN);

		pti = proto_tree_add_uint_format(xip_tree, hf_xip_payload_len,
 		 tvb, XIPH_PLEN, 2, plen, "Payload Length: %u bytes", plen);

		if (tvb_length_remaining(tvb, hlen) != plen)
			expert_add_info_format(pinfo, pti, PI_MALFORMED,
			 PI_ERROR, "Payload length field (%d bytes) does not match actual payload length (%d bytes)", plen, tvb_length_remaining(tvb, hlen));

		proto_tree_add_item(xip_tree, hf_xip_hop_limit, tvb,
		 XIPH_HOPL, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_num_dst, tvb,
		 XIPH_NDST, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(xip_tree, hf_xip_num_src, tvb,
		 XIPH_NSRC, 1, ENC_BIG_ENDIAN);

		if (last_node == XIA_ENTRY_NODE_INDEX)
			format = "(entry node)";

		proto_tree_add_uint_format(xip_tree, hf_xip_last_node, tvb,
		 XIPH_LSTN, 1, last_node, "Last Node: %u %s", last_node,
		 format);

		/* Construct Destination DAG subtree. */
		if (dst_nodes > 0) {
			ti = proto_tree_add_item(xip_tree, hf_xip_dst_dag,
			 tvb, XIPH_DSTD, dst_nodes * NODE_SIZE, ENC_BIG_ENDIAN);

			dst_tree = proto_item_add_subtree(ti, ett_xip_ddag);

			tvb_memcpy(tvb, (guint8 *)(&dst), XIPH_DSTD,
			 NODE_SIZE * dst_nodes);

			xia_ntop(&dst, dst_string, XIA_MAX_STRADDR_SIZE, 1);

			display_dag(dst_tree, hf_xip_dst_dag_entry, tvb,
			 XIPH_DSTD, dst_string, dst_nodes);
		}

		/* Construct Source DAG subtree. */
		if (src_nodes > 0) {
			ti = proto_tree_add_item(xip_tree, hf_xip_src_dag, tvb,
			 src_offset, src_nodes * NODE_SIZE, ENC_BIG_ENDIAN);

			src_tree = proto_item_add_subtree(ti, ett_xip_sdag);

			tvb_memcpy(tvb, (guint8 *)(&src), src_offset,
			 NODE_SIZE * src_nodes);

			xia_ntop(&src, src_string, XIA_MAX_STRADDR_SIZE, 1);

			display_dag(src_tree, hf_xip_src_dag_entry, tvb,
			 src_offset, src_string, src_nodes);
		}
	}

	if (1) {
	//if (next_diss == XID_TYPE_XDP || next_diss == XID_TYPE_AD) {
		next_tvb = tvb_new_subset(tvb, hlen, -1, -1);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}

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
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

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
		   BASE_DEC, NULL, 0x0, NULL, HFILL }},

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

	data_handle = find_dissector("data");
}
