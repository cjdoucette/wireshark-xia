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

#define XIDTYPE_HID 	(__cpu_to_be32(0x11))
#define XID_LEN		20
#define NWPH_MIN_LEN	36

#define NWP_VERSION	0x01

/*
 * Note: To add a new NWP packet type, include:
 *
 * * A new type definition directive.
 * * A new entry in the map_types function.
 * * A dissect_nwp_<new_type> function.
 * * A new entry in dissect_nwp that calls the above function.
 *
 */

#define NWP_TYPE_ANNOUNCEMENT	0x01
#define NWP_TYPE_NEIGH_LIST	0x02
#define NWP_TYPE_MAX		0x03

#define ETHERTYPE_NWP		0xC0DF	   /* Neighborhood Watch Protocol */
				        /* [NOT AN OFFICIALLY REGISTERED ID] */

/* Offsets of fields within a NWP header. */
#define NWPH_VERS	0
#define NWPH_TYPE	1
#define NWPH_HIDC	2
#define NWPH_HLEN	3

#define NWPH_HWAD	4
#define NWPH_NLST	4

static int proto_nwp = -1;

/* Header fields for all NWP headers. */
static int hf_nwp_version = -1;
static int hf_nwp_type = -1;
static int hf_nwp_hid_count = -1;
static int hf_nwp_haddr_len = -1;

/* Header fields for NWP Announcement packets. */
static int hf_nwp_haddr = -1;
static int hf_nwp_hids = -1;
static int hf_nwp_hid = -1;

/* Header fields for NWP Neighbor List packets. */
static int hf_nwp_neigh_list = -1;
static int hf_nwp_neigh = -1;
static int hf_nwp_neigh_ha = -1;

/* Subtrees. */
static gint ett_nwp = -1;
static gint ett_nwp_ann_hids = -1;
static gint ett_nwp_neigh_list = -1;

/* Convert a stream of u8 bytes to a XIA XID. */
static gchar *
str_of_xid(gchar **dest_str, u8 *id)
{
	struct xia_xid xid;
	*dest_str = (char *)ep_alloc(XIA_MAX_STRXID_SIZE + 1);
	xid.xid_type = XIDTYPE_HID;
	memcpy(xid.xid_id, id, XIA_XID_MAX);
	xia_xidtop(&xid, (gchar *)*dest_str, XIA_MAX_STRXID_SIZE);
}

/* Map a type number to a type string for display. */
static gchar *
map_types(guint8 type)
{
	switch (type) {
	case NWP_TYPE_ANNOUNCEMENT:
		return "NWP Announcement (0x01)";
	case NWP_TYPE_NEIGH_LIST:
		return "NWP Neighborhood List (0x02)";
	default:
		return "Invalid NWP packet type";
	}
}

/* Convert an NWP header's hardware address to a string. */
static gchar *
tvb_nwphrdaddr_to_str(tvbuff_t *tvb, gint offset, int ad_len)
{
	if (ad_len == 0)
		return "<No address>";
	if (ad_len == 6)
		return tvb_ether_to_str(tvb, offset);

	return tvb_bytes_to_str(tvb, offset, ad_len);
}

/* Process the neighbor list in a NWP packet. */
static void
process_neighs(proto_tree *list_tree, tvbuff_t *tvb, guint8 ha_len)
{
	guint8 ha_count, i, j, offset, hid_count;
	gchar *byte_str, *xid_str, *ha, *ha_begin;

	offset = NWPH_NLST;
	hid_count = tvb_get_guint8(tvb, NWPH_HIDC);
	byte_str = (gchar *)ep_alloc(2*XID_LEN + 1);
	ha = (gchar *)ep_alloc(2*ha_len + 1);
	ha_begin = ha;

	for (i = 0; i < hid_count; i++) {

		byte_str = tvb_get_string(tvb, offset, XID_LEN);
		str_of_xid(&xid_str, (u8 *)byte_str);

		proto_tree_add_string_format(list_tree, hf_nwp_neigh,
		       tvb, offset, XID_LEN, xid_str, "%s", xid_str);

		offset += XID_LEN;
		ha_count = tvb_get_guint8(tvb, offset);
		offset++;

		for (j = 0; j < ha_count; j++) {

			ha = tvb_nwphrdaddr_to_str(tvb, offset, ha_len);
			proto_tree_add_string_format(list_tree, hf_nwp_haddr,
				    		     tvb, offset, ha_len, ha,
					            "    %d: %s", j + 1, ha);
			offset += ha_len;
		}
	}
}

/* Dissector for NWP Announcement packets. */
static void
dissect_nwp_ann(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nwp_tree,
		guint8 ha_len)
{
	proto_tree *hid_tree = NULL;
	proto_item *ti = NULL;

	gchar *byte_str, *xid_str, *ha, *ha_begin;
	guint8 hid_count, i;

	guint8 off = 0;
	byte_str = (gchar *)ep_alloc(2*XID_LEN + 1);
	ha = (gchar *)ep_alloc(2*ha_len + 1);
	ha_begin = ha;

	hid_count = tvb_get_guint8(tvb, NWPH_HIDC);

	col_add_str(pinfo->cinfo, COL_INFO, "NWP Announcement");

	ha = tvb_nwphrdaddr_to_str(tvb, NWPH_HWAD, ha_len);

	proto_tree_add_string_format(nwp_tree, hf_nwp_haddr, tvb, NWPH_HWAD,
			  	    ha_len, ha, "Hardware Address: %s", ha);

	ti = proto_tree_add_item(nwp_tree, hf_nwp_hids, tvb,
		    NWPH_HWAD + ha_len, -1, ENC_BIG_ENDIAN);

	hid_tree = proto_item_add_subtree(ti, ett_nwp_ann_hids);

	for (i = 0; i < hid_count; i++) {

		byte_str = tvb_get_string(tvb, NWPH_HWAD + ha_len + off,
							       XID_LEN);
		str_of_xid(&xid_str, (u8 *)byte_str);

		proto_tree_add_string_format(hid_tree, hf_nwp_hid, tvb,
		      NWPH_HWAD + ha_len + off, XID_LEN, xid_str, "%s",
							      xid_str);
		off += XID_LEN;
	}
}

/* Dissector for NWP Neighbor List packets. */
static void
dissect_nwp_nl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *nwp_tree,
	       guint8 ha_len)
{
	proto_tree *list_tree = NULL;
	proto_item *ti = NULL;

	col_add_str(pinfo->cinfo, COL_INFO, "NWP Neighbor List");

	ti = proto_tree_add_item(nwp_tree, hf_nwp_neigh_list,
		 	 tvb, NWPH_NLST, -1, ENC_BIG_ENDIAN);

	list_tree = proto_item_add_subtree(ti, ett_nwp_neigh_list);

	process_neighs(list_tree, tvb, ha_len);
}

static int
dissect_nwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *nwp_tree = NULL;
	proto_item *ti = NULL;

	guint8 type;
	guint *type_str;
	guint8 ha_len;

	type = tvb_get_guint8(tvb, NWPH_TYPE);
	type_str = map_types(type);
	ha_len = tvb_get_guint8(tvb, NWPH_HLEN);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NWP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {

		/* Construct protocol tree. */
		ti = proto_tree_add_item(tree, proto_nwp, tvb, 0, -1, ENC_NA);

		nwp_tree = proto_item_add_subtree(ti, ett_nwp);

		/* Add header fields to tree. */
		proto_tree_add_item(nwp_tree, hf_nwp_version, tvb,
				    NWPH_VERS, 1, ENC_BIG_ENDIAN);

		proto_tree_add_string(nwp_tree, hf_nwp_type, tvb,
				    NWPH_TYPE, 1, type_str);

		proto_tree_add_item(nwp_tree, hf_nwp_hid_count, tvb,
				    NWPH_HIDC, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(nwp_tree, hf_nwp_haddr_len, tvb,
				    NWPH_HLEN, 1, ENC_BIG_ENDIAN);

		switch (type) {

		case NWP_TYPE_ANNOUNCEMENT:

			dissect_nwp_ann(tvb, pinfo, nwp_tree, ha_len);
			break;

		case NWP_TYPE_NEIGH_LIST:

			dissect_nwp_nl(tvb, pinfo, nwp_tree, ha_len);
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
		{ "Type", "nwp.type", FT_STRINGZ,
		   BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_nwp_hid_count,
		{ "HID Count", "nwp.hid_count", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

		{ &hf_nwp_haddr_len,
		{ "Hardware Address Length", "nwp.haddr_len", FT_UINT8,
		   BASE_DEC, NULL, 0x0,	NULL, HFILL }},

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

