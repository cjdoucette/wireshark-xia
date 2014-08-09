/* packet-nwp.c
 * Routines for NWP dissection.
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
#include "packet-xip-dag.h"

typedef unsigned char 	u8;

#define XID_LEN		20
#define NWPH_MIN_LEN	36

#define NWP_VERSION	0x01
#define MONITORING	0

/*
 * Note: To add a new NWP packet type, include:
 *
 * * A new type definition directive.
 * * A new entry in the map_type_name_nwp function.
 * * A dissect_nwp_<new_type> function.
 * * A new entry in dissect_nwp that calls the above function.
 *
 */

#define NWP_TYPE_ANNOUNCEMENT	0x01
#define NWP_TYPE_NEIGH_LIST	0x02
#define NWP_TYPE_PING		0x03
#define NWP_TYPE_ACK		0x04
#define NWP_TYPE_REQ_PING	0x05
#define NWP_TYPE_REQ_ACK	0x06
#define NWP_TYPE_INV_PING	0x07
#define NWP_TYPE_MAX		0x08

const value_string nwptype_vals[] = {
	{ NWP_TYPE_ANNOUNCEMENT,	"NWP Announcement (0x01)" },
	{ NWP_TYPE_NEIGH_LIST,		"NWP Neighborhood List (0x02)" },
	{ NWP_TYPE_PING,		"NWP Ping (0x03)" },
	{ NWP_TYPE_ACK,			"NWP Ack (0x04)" },
	{ NWP_TYPE_REQ_PING,		"NWP Request Ping (0x05)" },
	{ NWP_TYPE_REQ_ACK,		"NWP Request Ack (0x06)" },
	{ NWP_TYPE_INV_PING,		"NWP Investigative Ping (0x07)" },
	{ 0,				NULL }
};

#ifndef ETHERTYPE_NWP
#define ETHERTYPE_NWP		0xC0DF	   /* Neighborhood Watch Protocol */
#endif				        /* [NOT AN OFFICIALLY REGISTERED ID] */

/* Offsets of fields in NWP Announcements/Neighbor Lists. */
#define NWPH_VERS	0
#define NWPH_TYPE	1
#define NWPH_HIDC	2
#define NWPH_HLEN	3

#define NWPH_NLST	4
#if MONITORING
#define NWPH_ANN_STAT	4
#define NWPH_HWAD	8
#else
#define NWPH_HWAD	4
#endif

/* Offsets of fields in NWP Monitoring packets. */
#define NWPH_CLOK	4
#define NWPH_SHRD	8

static int proto_nwp = -1;

/* Header fields for all NWP headers. */
static int hf_nwp_version = -1;
static int hf_nwp_type = -1;
static int hf_nwp_haddr_len = -1;

/* Header fields for both NWP Announcement and Neighbor List packets. */
static int hf_nwp_hid_count = -1;
static int hf_nwp_status    = -1;
static int hf_nwp_ann_clock = -1;

/* Header fields for NWP Announcement packets. */
static int hf_nwp_haddr = -1;
static int hf_nwp_hids = -1;
static int hf_nwp_hid = -1;

/* Header fields for NWP Neighbor List packets. */
static int hf_nwp_neigh_list  = -1;
static int hf_nwp_neigh       = -1;
static int hf_nwp_neigh_ha    = -1;
static int hf_nwp_num_devices = -1;

/* Header fields for NWP Monitoring packets. */
static int hf_nwp_clock = -1;
static int hf_nwp_src_addr = -1;
static int hf_nwp_dst_addr = -1;
static int hf_nwp_inv_addr = -1;

/* Subtrees. */
static gint ett_nwp = -1;
static gint ett_nwp_ann_hids = -1;
static gint ett_nwp_neigh_list = -1;

static inline gboolean
is_monitoring(guint8 type)
{
	return (type == NWP_TYPE_PING		||
		type == NWP_TYPE_ACK		||
		type == NWP_TYPE_REQ_PING	||
		type == NWP_TYPE_REQ_ACK	||
		type == NWP_TYPE_INV_PING);
}

/* Convert a stream of u8 bytes to a XIA XID. */
static void
str_of_xid(gchar **dest_str, u8 *id)
{
	struct xia_xid xid;
	*dest_str = (gchar *)malloc(XIA_MAX_STRXID_SIZE + 1);
	xid.xid_type = XIDTYPE_HID;
	memcpy(xid.xid_id, id, XIA_XID_MAX);
	xia_xidtop(&xid, (gchar *)*dest_str, XIA_MAX_STRXID_SIZE);
}

/* Convert an NWP header's hardware address to a string. */
static inline gchar *
tvb_nwphrdaddr_to_str(tvbuff_t *tvb, gint offset, int ad_len)
{
	if (ad_len == 0)
		return (gchar *)"<No address>";
	if (ad_len == 6)
		return (gchar *)tvb_ether_to_str(tvb, offset);

	return tvb_bytes_to_str(tvb, offset, ad_len);
}

/* Process the neighbor list in a NWP packet. */
static void
process_neighs(proto_tree *list_tree, tvbuff_t *tvb, guint8 ha_len)
{
	guint8 ha_count, i, j, offset, hid_count;
	gchar *byte_str, *xid_str, *ha, *copy;
	guint32 status;

	offset = NWPH_NLST;
	hid_count = tvb_get_guint8(tvb, NWPH_HIDC);
	ha = (gchar *)malloc(2*ha_len + 1);

	for (i = 0; i < hid_count; i++) {

		byte_str = (gchar *)malloc(2 * XID_LEN + 1);
		byte_str = tvb_get_string(tvb, offset, XID_LEN);
		str_of_xid(&xid_str, (u8 *)byte_str);
		copy = (gchar *)calloc(strlen(xid_str) + strlen("hid") - 4, 1);
		map_types(xid_str, copy, XIDTYPE_HID);

		proto_tree_add_string_format(list_tree, hf_nwp_neigh,
		 tvb, offset, XID_LEN, copy, "HID %d: %s", i + 1, copy);

		offset += XID_LEN;
		ha_count = tvb_get_guint8(tvb, offset);

		proto_tree_add_string_format(list_tree, hf_nwp_num_devices,
		 tvb, offset, 1, &ha_count, "  Number of Devices: %d",
		 ha_count);

		offset++;

		for (j = 0; j < ha_count; j++) {

			ha = tvb_nwphrdaddr_to_str(tvb, offset, ha_len);
			status = tvb_get_ntohl(tvb, offset + ha_len);

			proto_tree_add_string_format(list_tree, hf_nwp_haddr,
			 tvb, offset, ha_len, ha,
			 "  %d: Hardware Address: %s", j + 1, ha);
#if MONITORING
			proto_tree_add_string_format(list_tree, hf_nwp_status,
			 tvb, offset + ha_len, 4, (char *)&status,
			 "     Status: %s", (0x80000000 & status) ? "Alive"
								 : "Failed");
			proto_tree_add_string_format(list_tree,
			 hf_nwp_ann_clock, tvb, offset + ha_len, 4,
			 (gchar *)&status,
			 "     Clock: 0x%x", 0x7FFFFFFF & status);
#endif
			offset += ha_len + 4;
		}


		free(copy);
		free(xid_str);
		free(byte_str);
	}
}

/* Dissector for NWP Announcement packets. */
static void
dissect_nwp_ann(tvbuff_t *tvb, proto_tree *nwp_tree, guint8 ha_len)
{
	proto_tree *hid_tree = NULL;
	proto_item *ti = NULL;

	gchar *byte_str, *xid_str, *ha, *copy;
	guint8 hid_count, i;
	guint32 status;

	guint8 off = 0;
	ha = (gchar *)ep_alloc(2*ha_len + 1);

	hid_count = tvb_get_guint8(tvb, NWPH_HIDC);
	ha = tvb_nwphrdaddr_to_str(tvb, NWPH_HWAD, ha_len);

#if MONITORING
	status = tvb_get_ntohl(tvb, NWPH_ANN_STAT);

	proto_tree_add_string_format(nwp_tree, hf_nwp_status, tvb,
	 NWPH_ANN_STAT, 4, (gchar *)&status, "Active: %s",
	 (0x80000000 & status) ? "Alive" : "Failed");

	proto_tree_add_string_format(nwp_tree, hf_nwp_ann_clock, tvb,
	 NWPH_ANN_STAT, 4, (gchar *)&status, "Clock: 0x%x", 0x7FFFFFFF& status);
#endif

	proto_tree_add_string_format(nwp_tree, hf_nwp_haddr, tvb, NWPH_HWAD,
	 ha_len, ha, "Hardware Address: %s", ha);

	ti = proto_tree_add_item(nwp_tree, hf_nwp_hids, tvb,
	 NWPH_HWAD + ha_len, hid_count * XID_LEN, ENC_BIG_ENDIAN);

	hid_tree = proto_item_add_subtree(ti, ett_nwp_ann_hids);

	for (i = 0; i < hid_count; i++) {

		byte_str = tvb_get_string(tvb, NWPH_HWAD + ha_len + off,
		 XID_LEN);
		str_of_xid(&xid_str, (u8 *)byte_str);
		copy = (gchar *)calloc(strlen(xid_str) + strlen("hid") - 4, 1);
		map_types(xid_str, copy, XIDTYPE_HID);

		proto_tree_add_string_format(hid_tree, hf_nwp_hid, tvb,
		 NWPH_HWAD + ha_len + off, XID_LEN, copy, "%s", copy);
		off += XID_LEN;

		free(copy);
		free(xid_str);
	}
}

/* Dissector for NWP Neighbor List packets. */
static void
dissect_nwp_nl(tvbuff_t *tvb, proto_tree *nwp_tree, guint8 ha_len)
{
	proto_tree *list_tree = NULL;
	proto_item *ti = NULL;

	ti = proto_tree_add_item(nwp_tree, hf_nwp_neigh_list,
	 tvb, NWPH_NLST, -1, ENC_BIG_ENDIAN);

	list_tree = proto_item_add_subtree(ti, ett_nwp_neigh_list);

	process_neighs(list_tree, tvb, ha_len);
}

/* Dissectors for NWP Monitoring packets. */
static void
dissect_nwp_monitoring(tvbuff_t *tvb, proto_tree *nwp_tree, guint8 ha_len,
	guint8 type)
{
	gchar *src_ha, *dst_ha, *inv_ha;
	guint32 clock;

	clock = tvb_get_ntohl(tvb, NWPH_CLOK);
	proto_tree_add_string_format(nwp_tree, hf_nwp_clock, tvb,
	 NWPH_CLOK, 4, (gchar *)&clock, "Sender's Clock: 0x%x", clock);

	src_ha = tvb_nwphrdaddr_to_str(tvb, NWPH_SHRD, ha_len);
	proto_tree_add_string_format(nwp_tree, hf_nwp_src_addr, tvb,
	 NWPH_SHRD, ha_len, src_ha, "Source Hardware Address: %s", src_ha);

	dst_ha = tvb_nwphrdaddr_to_str(tvb, NWPH_SHRD + ha_len, ha_len);
	proto_tree_add_string_format(nwp_tree, hf_nwp_dst_addr, tvb,
	 NWPH_SHRD + ha_len, ha_len, dst_ha, "Destination Hardware Address: %s",
	 dst_ha);

	if (type != NWP_TYPE_PING && type != NWP_TYPE_ACK) {
		inv_ha = tvb_nwphrdaddr_to_str(tvb, NWPH_SHRD+2*ha_len, ha_len);
		proto_tree_add_string_format(nwp_tree, hf_nwp_inv_addr, tvb,
	 	 NWPH_SHRD + 2 * ha_len, ha_len, inv_ha,
		 "Investigative Hardware Address: %s", inv_ha);
	}
}

static int
dissect_nwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	__attribute__((unused))void *data)
{
	proto_tree *nwp_tree = NULL;
	proto_item *ti = NULL;

	guint8 type = tvb_get_guint8(tvb, NWPH_TYPE);
	const gchar *type_str = val_to_str(type, nwptype_vals, "%s");
	guint8 ha_len = tvb_get_guint8(tvb, NWPH_HLEN);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NWP");
	col_add_str(pinfo->cinfo, COL_INFO, type_str);

	if (tree) {
		/* Construct protocol tree. */
		ti = proto_tree_add_item(tree, proto_nwp, tvb, 0, -1, ENC_NA);
		nwp_tree = proto_item_add_subtree(ti, ett_nwp);

		/* Add header fields to tree. */
		proto_tree_add_item(nwp_tree, hf_nwp_version, tvb,
		 NWPH_VERS, 1, ENC_BIG_ENDIAN);

		proto_tree_add_string(nwp_tree, hf_nwp_type, tvb,
		 NWPH_TYPE, 1, type_str);

#if MONITORING
		if (is_monitoring(type)) {
			proto_tree_add_item(nwp_tree, hf_nwp_haddr_len, tvb,
		 	 NWPH_HLEN, 1, ENC_BIG_ENDIAN);
			dissect_nwp_monitoring(tvb, nwp_tree, ha_len, type);
			return tvb_length(tvb);
		}
#endif

		proto_tree_add_item(nwp_tree, hf_nwp_hid_count, tvb,
		 NWPH_HIDC, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(nwp_tree, hf_nwp_haddr_len, tvb,
		 NWPH_HLEN, 1, ENC_BIG_ENDIAN);

		switch (type) {
		case NWP_TYPE_ANNOUNCEMENT:
			dissect_nwp_ann(tvb, nwp_tree, ha_len);
			break;
		case NWP_TYPE_NEIGH_LIST:
			dissect_nwp_nl(tvb, nwp_tree, ha_len);
			break;
		default:
			break;
		}
	}

	return tvb_length(tvb);
}

void
proto_register_nwp(void)
{
	static hf_register_info hf[] = {

		{ &hf_nwp_version,
		{ "Version", "nwp.version", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_type,
		{ "Type", "nwp.type", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_hid_count,
		{ "HID Count", "nwp.hid_count", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_haddr_len,
		{ "Hardware Address Length", "nwp.haddr_len", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_num_devices,
		{ "Number of Devices", "nwp.num_devices", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_status,
		{ "Status", "nwp.status", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_ann_clock,
		{ "Clock", "nwp.clock", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_haddr,
		{ "Hardware Address", "nwp.haddr", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_hids,
		{ "HIDs", "nwp.hids", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_hid,
		{ "HID", "nwp.hid", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_list,
		{ "Neighbor List", "nwp.neigh_list", FT_NONE,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh,
		{ "Neighbor", "nwp.neigh", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_neigh_ha,
		{ "Neighbor Hardware Address", "nwp.neigh_ha", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_clock,
		{ "Sender's Clock", "nwp.clock", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_src_addr,
		{ "Source Hardware Address", "nwp.src_addr", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_dst_addr,
		{ "Destination Hardware Address", "nwp.dst_addr", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_inv_addr,
		{ "Investigative Hardware Address", "nwp.inv_addr", FT_STRING,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_nwp,
		&ett_nwp_ann_hids,
		&ett_nwp_neigh_list
	};


	proto_nwp = proto_register_protocol(
		"Neighborhood Watch Protocol",
		"NWP",
	        "nwp");

	proto_register_field_array(proto_nwp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nwp(void)
{
	dissector_handle_t nwp_handle;
	nwp_handle = new_create_dissector_handle(dissect_nwp, proto_nwp);
	dissector_add_uint("ethertype", ETHERTYPE_NWP, nwp_handle);
}
