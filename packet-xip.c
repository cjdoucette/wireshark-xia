/* packet-xip.c
 * Routines for XIP dissection
 * Copyright 2014, Cody Doucette <doucette@bu.edu>
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
#include <epan/in_cksum.h>
#include <epan/proto.h>
#include <ipproto.h>
#include "packet-xip-dag.h"
#include "packet-xip-dag-userland.h"

/* XIP constants. */
#define XIPH_MIN_LEN	36
#define NODE_SIZE	28
#define ETHERTYPE_XIP	0xC0DE
#define XID_LEN		20

/* Offsets of fields within an XIP header. */
#define XIPH_VERS	0
#define XIPH_NXTH	1
#define XIPH_PLEN	2
#define XIPH_HOPL	4
#define XIPH_NDST	5
#define XIPH_NSRC	6
#define XIPH_LSTN	7
#define XIPH_DSTD	8

static int proto_xip			= -1;

/* XIP header fields. */
static int hf_xip_version		= -1;
static int hf_xip_next_hdr		= -1;
static int hf_xip_payload_len		= -1;
static int hf_xip_hop_limit		= -1;
static int hf_xip_num_dst		= -1;
static int hf_xip_num_src		= -1;
static int hf_xip_last_node		= -1;
static int hf_xip_dst_dag		= -1;
static int hf_xip_dst_dag_entry		= -1;
static int hf_xip_src_dag		= -1;
static int hf_xip_src_dag_entry		= -1;

/* Serval header fields. */
static int hf_xip_serval		= -1;
static int hf_xip_serval_hl		= -1;
static int hf_xip_serval_proto		= -1;
static int hf_xip_serval_check		= -1;
static int hf_serval_checksum_good	= -1;
static int hf_serval_checksum_bad	= -1;
static int hf_xip_serval_ext_type	= -1;
static int hf_xip_serval_ext_length	= -1;

/* Serval Control Extension header fields. */
static int hf_xip_serval_cext		= -1;
static int hf_xip_serval_cext_flags	= -1;
static int hf_xip_serval_cext_syn	= -1;
static int hf_xip_serval_cext_rsyn	= -1;
static int hf_xip_serval_cext_ack	= -1;
static int hf_xip_serval_cext_nack	= -1;
static int hf_xip_serval_cext_rst	= -1;
static int hf_xip_serval_cext_fin	= -1;
static int hf_xip_serval_cext_verno	= -1;
static int hf_xip_serval_cext_ackno	= -1;
static int hf_xip_serval_cext_nonce	= -1;

/* Dissector trees. */
static gint ett_xip			= -1;
static gint ett_xip_ddag		= -1;
static gint ett_xip_sdag		= -1;
static gint ett_serval			= -1;
static gint ett_serval_checksum		= -1;
static gint ett_serval_cext		= -1;
static gint ett_serval_cext_flags	= -1;

/* Next dissector handles. */
static dissector_handle_t data_handle;
static dissector_handle_t udp_handle;
static dissector_handle_t tcp_handle;

/* Serval constants. */
#define XIA_SERVAL_EXT_TYPE_MASK	0xFF00
#define XIA_SERVAL_CEXT_TYPE		0
#define XIA_NEXT_DATA			0
#define XIA_NEXT_TCP			6
#define XIA_NEXT_UDP			17

static void
display_dag(proto_tree *tr, int hf, tvbuff_t *tvb, guint8 off, char *buf,
	guint8 num_nodes)
{
	gchar *p =  strtok(buf, "\n");
	guint8 i;
	for (i = 0; i < num_nodes; i++) {
		guint32 type = tvb_get_ntohl(tvb, off + (i * NODE_SIZE));
		const gchar *name = val_to_str(type, xidtype_vals, "%s");
		gchar *copy = (gchar *)calloc(strlen(p) + strlen(name) - 4, 1);
		map_types(p, copy, type);
		proto_tree_add_string_format(tr, hf, tvb,
		 off + (i * NODE_SIZE), NODE_SIZE, copy, "%s", copy);
		p = strtok(NULL, "\n");
		free(copy);
	}
}


/*
 *	Serval Control Extension Header
 */

#define XIA_SERVAL_CEXT_FLAGS_WIDTH	8
#define XIA_SERVAL_CEXT_NONCE_SIZE	8

static const gchar *serval_cext_flags[] = {
	"RES",	/* Reserved. */
	"RES",	/* Reserved. */
	"FIN",
	"RST",
	"NACK",
	"ACK",
	"RSYN",
	"SYN",
};

static void
display_serval_cext(tvbuff_t *tvb, proto_tree *serval_tree, guint8 offset,
	guint8 length)
{
	proto_tree *cext_tree, *cext_flags_tree;
	proto_item *ti;
	gint8 flags, bit;
	gboolean found_flag = FALSE;

	/* Create Serval Control Extension tree. */
	ti = proto_tree_add_item(serval_tree, hf_xip_serval_cext, tvb,
	 offset, length, ENC_BIG_ENDIAN);
	cext_tree = proto_item_add_subtree(ti, ett_serval_cext);

	/* Add extension type. */
	proto_tree_add_item(cext_tree, hf_xip_serval_ext_type, tvb,
	 offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Add extension length. */
	proto_tree_add_uint_format(cext_tree, hf_xip_serval_ext_length,
	 tvb, offset, 1, length, "Extension Length: %u bytes", length);
	offset++;

	/* Create Serval Control Extension flags tree. */
	ti = proto_tree_add_item(cext_tree, hf_xip_serval_cext_flags,
	 tvb, offset, 1, ENC_BIG_ENDIAN);
	cext_flags_tree = proto_item_add_subtree(ti, ett_serval_cext_flags);

	/* Add flag strings to tree header, so that the flags can
	 * easily be seen without having to open the tree.
	 */
	flags = tvb_get_guint8(tvb, offset);
	for (bit = 7; bit >= 0; bit--) {
		if (flags & (1 << bit)) {
			if (!found_flag) {
				proto_item_append_text(ti, " (");
				found_flag = TRUE;
			} else {
				proto_item_append_text(ti, ", ");
			}
			proto_item_append_text(ti, "%s",
			 serval_cext_flags[bit]);
		}
	}
	if (found_flag)
		proto_item_append_text(ti, ")");

	/* Add individual flag fields. */
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_syn, tvb, (offset * 8) + 0,
	 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_rsyn, tvb, (offset * 8) + 1,
	 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_ack, tvb, (offset * 8) + 2,
	 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_nack, tvb, (offset * 8) + 3,
	 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_rst, tvb, (offset * 8) + 4,
	 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(cext_flags_tree,
	 hf_xip_serval_cext_fin, tvb, (offset * 8) + 5,
	 1, ENC_BIG_ENDIAN);
	/* Skip two bits for res1. */
	offset++;

	/* Skip a byte for res2. */
	offset++;

	/* Add verification number. */
	proto_tree_add_item(cext_tree, hf_xip_serval_cext_verno,
	 tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add acknowledgement number. */
	proto_tree_add_item(cext_tree, hf_xip_serval_cext_ackno,
	 tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	/* Add nonce. */
	proto_tree_add_string(cext_tree, hf_xip_serval_cext_nonce,
	 tvb, offset, 8, tvb_bytes_to_str(tvb, offset,
	 XIA_SERVAL_CEXT_NONCE_SIZE));
	offset += 8;
}

/*
 *	Serval Extension Header
 */

static int
display_serval_ext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *serval_tree,
	guint8 offset)
{
	proto_item *ti;
	guint8 type = tvb_get_guint8(tvb, offset) & XIA_SERVAL_EXT_TYPE_MASK;
	guint8 length = tvb_get_guint8(tvb, offset + 1);

	switch (type) {
	case XIA_SERVAL_CEXT_TYPE:
		display_serval_cext(tvb, serval_tree, offset, length);
		break;
	default:
		expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
		 "Unrecognized Serval extension header type: 0x%02x", type);
		break;
	}

	return offset + length;
}

/*
 *	Serval Header
 */

static int
display_serval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *xip_tree,
	guint8 sh_offset, guint8 *serval_next_hdr)
{
	proto_tree *serval_tree = NULL;
	proto_tree *checksum_tree = NULL;
	proto_item *ti;
	proto_item *cti;

	guint8 offset;
	guint8 sh_len;
	guint8 next_header;
	guint16 packet_checksum;
	guint16 actual_checksum;
	vec_t cksum_vec[1];

	offset = sh_offset;

	/* Get Serval header length. */
	sh_len = tvb_get_guint8(tvb, sh_offset) << 2;
	/* Get Serval next header. */
	next_header = tvb_get_guint8(tvb, sh_offset + 1);
	*serval_next_hdr = next_header;
	/* Get Serval checksum. */
	packet_checksum = tvb_get_ntohs(tvb, sh_offset + 2);

	/* Create Serval header tree. */
	ti = proto_tree_add_item(xip_tree, hf_xip_serval,
	 tvb, sh_offset, sh_len, ENC_BIG_ENDIAN);
	serval_tree = proto_item_add_subtree(ti, ett_serval);

	/* Add Serval header length. */
	proto_tree_add_uint_format(serval_tree, hf_xip_serval_hl, tvb,
	 offset, 1, sh_len, "Header Length: %u bytes", sh_len);
	offset++;

	/* Add Serval next header. */
	if (next_header == XIA_NEXT_TCP || next_header == XIA_NEXT_UDP)
		proto_tree_add_uint_format(serval_tree, hf_xip_serval_proto,
		 tvb, offset, 1, next_header, "Next Header: %u (%s)",
		 next_header, next_header == XIA_NEXT_TCP ? "TCP" : "UDP");
	else
		proto_tree_add_item(serval_tree, hf_xip_serval_proto, tvb,
		 offset, 1, ENC_BIG_ENDIAN);
	offset++;

	/* Compute checksum. */
	cksum_vec[0].ptr = tvb_get_ptr(tvb, sh_offset, sh_len);
	cksum_vec[0].len = sh_len;
	actual_checksum = in_cksum(&cksum_vec[0], 1);

	if (actual_checksum == 0) {
		/* Add Serval checksum as correct. */
		cti = proto_tree_add_uint_format(serval_tree,
		 hf_xip_serval_check, tvb, offset, 2, packet_checksum,
		 "Header checksum: 0x%04x [correct]", packet_checksum);

		checksum_tree = proto_item_add_subtree(cti,
		 ett_serval_checksum);

		cti = proto_tree_add_boolean(checksum_tree,
		 hf_serval_checksum_good, tvb, offset, 2, TRUE);
		PROTO_ITEM_SET_GENERATED(cti);

		cti = proto_tree_add_boolean(checksum_tree,
		 hf_serval_checksum_bad, tvb, offset, 2, FALSE);
		PROTO_ITEM_SET_GENERATED(cti);
	} else {
		/* Add Serval checksum as incorrect. */
		cti = proto_tree_add_uint_format(serval_tree,
		 hf_xip_serval_check, tvb, offset, 2, packet_checksum,
		 "Header checksum: 0x%04x [incorrect, should be 0x%04x]",
		 packet_checksum,
		 in_cksum_shouldbe(packet_checksum, actual_checksum));

	        checksum_tree = proto_item_add_subtree(cti,
		 ett_serval_checksum);

		cti = proto_tree_add_boolean(checksum_tree,
		 hf_serval_checksum_good, tvb, offset, 2, FALSE);
		PROTO_ITEM_SET_GENERATED(cti);

		cti = proto_tree_add_boolean(checksum_tree,
		 hf_serval_checksum_bad, tvb, offset, 2, TRUE);
		PROTO_ITEM_SET_GENERATED(cti);

		expert_add_info_format(pinfo, cti, PI_CHECKSUM,
		 PI_ERROR, "Bad checksum");
	}
	offset += 2;

	/* If there's still more room, check for extension headers. */
	while (sh_offset + sh_len > offset)
		offset = display_serval_ext(tvb, pinfo, serval_tree, offset);

	return offset - sh_offset;
}

/*
 *	eXpressive Internet Protocol Header
 */

static int
dissect_xip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	__attribute__((unused))void *data)
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

	guint32 sink = tvb_get_ntohl(tvb, XIPH_DSTD +
	 (dst_nodes - 1) * NODE_SIZE);

	guint8 serval_next_hdr = 0;

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
		ti = proto_tree_add_item(tree, proto_xip,
		 tvb, 0, hlen, ENC_NA);
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

		proto_tree_add_uint_format(xip_tree, hf_xip_last_node, tvb,
		 XIPH_LSTN, 1, last_node, "Last Node: %u %s", last_node,
		 last_node == XIA_ENTRY_NODE_INDEX ? "(entry node)" : "");

		/* Construct Destination DAG subtree. */
		if (dst_nodes > 0) {
			ti = proto_tree_add_item(xip_tree, hf_xip_dst_dag,
			 tvb, XIPH_DSTD, dst_nodes * NODE_SIZE,
			 ENC_BIG_ENDIAN);
			dst_tree = proto_item_add_subtree(ti, ett_xip_ddag);

			tvb_memcpy(tvb, (guint8 *)(&dst), XIPH_DSTD,
			 NODE_SIZE * dst_nodes);

			xia_ntop(&dst, dst_string, XIA_MAX_STRADDR_SIZE, 1);

			display_dag(dst_tree, hf_xip_dst_dag_entry, tvb,
			 XIPH_DSTD, dst_string, dst_nodes);
		}

		/* Construct Source DAG subtree. */
		if (src_nodes > 0) {
			ti = proto_tree_add_item(xip_tree, hf_xip_src_dag,
			 tvb, src_offset, src_nodes * NODE_SIZE,
			 ENC_BIG_ENDIAN);
			src_tree = proto_item_add_subtree(ti, ett_xip_sdag);

			tvb_memcpy(tvb, (guint8 *)(&src), src_offset,
			 NODE_SIZE * src_nodes);

			xia_ntop(&src, src_string, XIA_MAX_STRADDR_SIZE, 1);

			display_dag(src_tree, hf_xip_src_dag_entry, tvb,
			 src_offset, src_string, src_nodes);
		}

		/* Add Serval header and extension headers, if necessary. */
		if (sink == XIDTYPE_FLOWID || sink == XIDTYPE_SRVCID)
			hlen += display_serval(tvb, pinfo, xip_tree,
			 src_offset + src_nodes * NODE_SIZE, &serval_next_hdr);
	}

	next_tvb = tvb_new_subset(tvb, hlen, -1, -1);
	switch (serval_next_hdr) {
	case XIA_NEXT_DATA:
		call_dissector(data_handle, next_tvb, pinfo, tree);
		break;
	case XIA_NEXT_UDP:
		call_dissector(udp_handle, next_tvb, pinfo, tree);
		break;
	case XIA_NEXT_TCP:
		call_dissector(tcp_handle, next_tvb, pinfo, tree);
		break;
	default:
		expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
		 "Unrecognized next header type: 0x%02x", serval_next_hdr);

		break;
	}
	return tvb_length(tvb);
}

void
proto_register_xip(void)
{
	static hf_register_info hf[] = {

		/* XIP Header. */

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
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		/* Serval Header. */

		{ &hf_xip_serval,
		{ "Serval", "xip.serval",
		   FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_hl,
		{ "Header Length", "xip.serval_hl", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_proto,
		{ "Next Header", "xip.serval_proto", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_check,
		{ "Checksum", "xip.serval_check", FT_UINT16,
		   BASE_HEX, NULL, 0x0,	NULL, HFILL }},

		{ &hf_serval_checksum_good,
		{ "Good Checksum", "xip.serval_checksum_good",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "True: checksum matches packet content; False: doesn't match content or not checked",
		  HFILL }},

		{ &hf_serval_checksum_bad,
		{ "Bad Checksum", "xip.serval_checksum_bad",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "True: checksum doesn't match packet content; False: matches content or not checked",
		  HFILL }},

		/* Serval Extension Header. */

		{ &hf_xip_serval_ext_type,
		{ "Extension Type", "xip.serval_ext_type", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_xip_serval_ext_length,
		{ "Extension Length", "xip.serval_proto", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		/* Serval Control Extension Header. */

		{ &hf_xip_serval_cext,
		{ "Serval Control Extension", "xip.serval_cext",
		   FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_flags,
		{ "Flags", "xip.serval_cext_flags", FT_UINT8, BASE_HEX,
		  NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_syn,
		{ "SYN", "xip.serval_cext_syn", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_rsyn,
		{ "RSYN", "xip.serval_cext_rsyn", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_ack,
		{ "ACK", "xip.serval_cext_ack", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_nack,
		{ "NACK", "xip.serval_cext_nack", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_rst,
		{ "RST", "xip.serval_cext_rst", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_fin,
		{ "FIN", "xip.serval_cext_fin", FT_BOOLEAN, BASE_NONE,
		  TFS(&tfs_set_notset), 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_verno,
		{ "Version Number", "xip.serval_cext_verno", FT_UINT32,
		  BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_ackno,
		{ "Acknowledgement Number", "xip.serval_cext_ackno",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_xip_serval_cext_nonce,
		{ "Nonce", "xip.serval_cext_nonce", FT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_xip,
		&ett_xip_ddag,
		&ett_xip_sdag,
		&ett_serval,
		&ett_serval_checksum,
		&ett_serval_cext,
		&ett_serval_cext_flags
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
	udp_handle = find_dissector("udp");
	tcp_handle = find_dissector("tcp");
}
