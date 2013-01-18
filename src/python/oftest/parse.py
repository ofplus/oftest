"""
OpenFlow message parsing functions
"""

import sys
import logging
from oftest import message
from match_list import match_list
import oftest.match as match
#from error import *
#from action import *
#from action_list import action_list
import oftest.cstruct as ofp




try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    load_contrib("mpls")
    #TODO This should really be in scapy!
    bind_layers(MPLS, MPLS, s=0)
except:
    sys.exit("Need to install scapy for packet parsing")

"""
of_message.py
Contains wrapper functions and classes for the of_message namespace
that are generated by hand.  It includes the rest of the wrapper
function information into the of_message namespace
"""

parse_logger = logging.getLogger("parse")
#parse_logger.setLevel(logging.DEBUG)

# These message types are subclassed
msg_type_subclassed = [
    ofp.OFPT_STATS_REQUEST,
    ofp.OFPT_STATS_REPLY,
    ofp.OFPT_ERROR
]

# Maps from sub-types to classes
stats_reply_to_class_map = {
    ofp.OFPST_DESC                      : message.desc_stats_reply,
    ofp.OFPST_FLOW                      : message.flow_stats_reply,
    ofp.OFPST_AGGREGATE                 : message.aggregate_stats_reply,
    ofp.OFPST_TABLE                     : message.table_stats_reply,
    ofp.OFPST_PORT                      : message.port_stats_reply,
    ofp.OFPST_QUEUE                     : message.queue_stats_reply,
    ofp.OFPST_GROUP                     : message.group_stats_reply,
    ofp.OFPST_GROUP_DESC                : message.group_desc_stats_reply
#    ofp.OFPST_EXPERIMENTER
}

stats_request_to_class_map = {
    ofp.OFPST_DESC                      : message.desc_stats_request,
    ofp.OFPST_FLOW                      : message.flow_stats_request,
    ofp.OFPST_AGGREGATE                 : message.aggregate_stats_request,
    ofp.OFPST_TABLE                     : message.table_stats_request,
    ofp.OFPST_PORT                      : message.port_stats_request,
    ofp.OFPST_QUEUE                     : message.queue_stats_request,
    ofp.OFPST_GROUP                     : message.group_stats_request,
    ofp.OFPST_GROUP_DESC                : message.group_desc_stats_request
#    ofp.OFPST_EXPERIMENTER
}

error_to_class_map = {
    ofp.OFPET_HELLO_FAILED              : message.hello_failed_error_msg,
    ofp.OFPET_BAD_REQUEST               : message.bad_request_error_msg,
    ofp.OFPET_BAD_ACTION                : message.bad_action_error_msg,
    ofp.OFPET_BAD_INSTRUCTION           : message.bad_instruction_error_msg,
    ofp.OFPET_BAD_MATCH                 : message.bad_match_error_msg,
    ofp.OFPET_FLOW_MOD_FAILED           : message.flow_mod_failed_error_msg,
    ofp.OFPET_GROUP_MOD_FAILED          : message.group_mod_failed_error_msg,
    ofp.OFPET_PORT_MOD_FAILED           : message.port_mod_failed_error_msg,
    ofp.OFPET_TABLE_MOD_FAILED          : message.table_mod_failed_error_msg,
    ofp.OFPET_QUEUE_OP_FAILED           : message.queue_op_failed_error_msg,
    ofp.OFPET_SWITCH_CONFIG_FAILED      : message.switch_config_failed_error_msg
}

# Map from header type value to the underlieing message class
msg_type_to_class_map = {
    ofp.OFPT_HELLO                      : message.hello,
    ofp.OFPT_ERROR                      : message.error,
    ofp.OFPT_ECHO_REQUEST               : message.echo_request,
    ofp.OFPT_ECHO_REPLY                 : message.echo_reply,
    ofp.OFPT_EXPERIMENTER               : message.experimenter,
    ofp.OFPT_FEATURES_REQUEST           : message.features_request,
    ofp.OFPT_FEATURES_REPLY             : message.features_reply,
    ofp.OFPT_GET_CONFIG_REQUEST         : message.get_config_request,
    ofp.OFPT_GET_CONFIG_REPLY           : message.get_config_reply,
    ofp.OFPT_SET_CONFIG                 : message.set_config,
    ofp.OFPT_PACKET_IN                  : message.packet_in,
    ofp.OFPT_FLOW_REMOVED               : message.flow_removed,
    ofp.OFPT_PORT_STATUS                : message.port_status,
    ofp.OFPT_PACKET_OUT                 : message.packet_out,
    ofp.OFPT_FLOW_MOD                   : message.flow_mod,
    ofp.OFPT_GROUP_MOD                  : message.group_mod,
    ofp.OFPT_PORT_MOD                   : message.port_mod,
    ofp.OFPT_TABLE_MOD                  : message.table_mod,
    ofp.OFPT_STATS_REQUEST              : message.stats_request,
    ofp.OFPT_STATS_REPLY                : message.stats_reply,
    ofp.OFPT_BARRIER_REQUEST            : message.barrier_request,
    ofp.OFPT_BARRIER_REPLY              : message.barrier_reply,
    ofp.OFPT_QUEUE_GET_CONFIG_REQUEST   : message.queue_get_config_request,
    ofp.OFPT_QUEUE_GET_CONFIG_REPLY     : message.queue_get_config_reply,
}

def _of_message_to_object(binary_string):
    """
    Map a binary string to the corresponding class.

    Appropriately resolves subclasses
    """
    hdr = ofp.ofp_header()
    hdr.unpack(binary_string)
    # FIXME: Add error detection
    if not hdr.type in msg_type_subclassed:
        return msg_type_to_class_map[hdr.type]()
    if hdr.type == ofp.OFPT_STATS_REQUEST:
        sub_hdr = ofp.ofp_stats_request()
        sub_hdr.unpack(binary_string[ofp.OFP_HEADER_BYTES:])
        try:
            obj = stats_request_to_class_map[sub_hdr.type]()
        except LookupError:
            obj = None
        return obj
    elif hdr.type == ofp.OFPT_STATS_REPLY:
        sub_hdr = ofp.ofp_stats_reply()
        sub_hdr.unpack(binary_string[ofp.OFP_HEADER_BYTES:])
        try:
            obj = stats_reply_to_class_map[sub_hdr.type]()
        except LookupError:
            obj = None
        return obj
    elif hdr.type == ofp.OFPT_ERROR:
        sub_hdr = ofp.ofp_error_msg()
        sub_hdr.unpack(binary_string[ofp.OFP_HEADER_BYTES:])
        return error_to_class_map[sub_hdr.type]()
    else:
        parse_logger.error("Cannot parse pkt to message")
        return None

def of_message_parse(binary_string, raw=False):
    """
    Parse an OpenFlow packet

    Parses a raw OpenFlow packet into a Python class, with class
    members fully populated.

    @param binary_string The packet (string) to be parsed
    @param raw If true, interpret the packet as an L2 packet.  Not
    yet supported.
    @return An object of some message class or None if fails
    Note that any data beyond that parsed is not returned

    """

    if raw:
        parse_logger.error("raw packet message parsing not supported")
        return None

    obj = _of_message_to_object(binary_string)
    if obj:
        obj.unpack(binary_string)
    return obj


def of_header_parse(binary_string, raw=False):
    """
    Parse only the header from an OpenFlow packet

    Parses the header from a raw OpenFlow packet into a
    an ofp_header Python class.

    @param binary_string The packet (string) to be parsed
    @param raw If true, interpret the packet as an L2 packet.  Not
    yet supported.
    @return An ofp_header object

    """

    if raw:
        parse_logger.error("raw packet message parsing not supported")
        return None

    hdr = ofp.ofp_header()
    hdr.unpack(binary_string)

    return hdr

map_wc_field_to_match_member = {
    'OFPFW_DL_VLAN'                 : 'dl_vlan',
    'OFPFW_DL_SRC'                  : 'dl_src',
    'OFPFW_DL_DST'                  : 'dl_dst',
    'OFPFW_DL_TYPE'                 : 'dl_type',
    'OFPFW_NW_PROTO'                : 'nw_proto',
    'OFPFW_TP_SRC'                  : 'tp_src',
    'OFPFW_TP_DST'                  : 'tp_dst',
    'OFPFW_NW_SRC_SHIFT'            : 'nw_src_shift',
    'OFPFW_NW_SRC_BITS'             : 'nw_src_bits',
    'OFPFW_NW_SRC_MASK'             : 'nw_src_mask',
    'OFPFW_NW_SRC_ALL'              : 'nw_src_all',
    'OFPFW_NW_DST_SHIFT'            : 'nw_dst_shift',
    'OFPFW_NW_DST_BITS'             : 'nw_dst_bits',
    'OFPFW_NW_DST_MASK'             : 'nw_dst_mask',
    'OFPFW_NW_DST_ALL'              : 'nw_dst_all',
    'OFPFW_DL_VLAN_PCP'             : 'dl_vlan_pcp',
    'OFPFW_NW_TOS'                  : 'nw_tos'
}


def parse_mac(mac_str):
    """
    Parse a MAC address

    Parse a MAC address ':' separated string of hex digits to an
    array of integer values.  '00:d0:05:5d:24:00' => [0, 208, 5, 93, 36, 0]
    @param mac_str The string to convert
    @return Array of 6 integer values
    """
    return map(lambda val:eval("0x" + val), mac_str.split(":"))

def parse_ip(ip_str):
    """
    Parse an IP address

    Parse an IP address '.' separated string of decimal digits to an
    host ordered integer.  '172.24.74.77' => 
    @param ip_str The string to convert
    @return Integer value
    """
    array = map(lambda val:eval(val),ip_str.split("."))
    val = 0
    for a in array:
        val <<= 8
        val += a
    return val

def packet_to_flow_match(packet):
    """
    Create a flow match that matches packet with the given wildcards

    @param packet The packet to use as a flow template
    @param pkt_format Currently only L2 is supported.  Will indicate the 
    overall packet type for parsing
    @return An ofp_match object if successful.  None if format is not
    recognized. If a Vlan ID is present, the match returned will contain 
    only eth_type, eth_dst, eth_src and Vlan fields.

    @todo check min length of packet
    @todo Check if packet is other than L2 format
    @todo implement other fields covered by OpenFlow 1.2 
    """
    match_ls = match_list()
    
    if Ether in packet:
        ether = packet[Ether]
        eth_type = match.eth_type(ether.type)
        eth_dst = match.eth_dst(parse_mac(ether.dst))
        eth_src = match.eth_src(parse_mac(ether.src))
        if Dot1Q not in packet:
            match_ls.tlvs.append(eth_type)
        match_ls.tlvs.append(eth_dst)
        match_ls.tlvs.append(eth_src)
    else:
        return match_ls

    if Dot1Q in packet:
        #TODO: nicer way to get last vlan tag?
        vlan = packet[Dot1Q:0]
        vlan_vid = match.vlan_vid(vlan.vlan)
        vlan_pcp = match.vlan_pcp(vlan.prio)
        match_ls.tlvs.append(vlan_vid)
        match_ls.tlvs.append(vlan_pcp)
        vlan_pl = vlan.payload
        while vlan_pl is not None and vlan_pl.name == Dot1Q.name:
            vlan = vlan_pl
            vlan_pl = vlan.payload
        eth_type = match.eth_type(vlan.type)
        match_ls.tlvs.append(eth_type)
    #TODO ARP

    if MPLS in packet:
        mpls = packet[MPLS:0]
        mpls_label = match.mpls_label(mpls.label)
        mpls_tc =  match.mpls_tc(mpls.cos)
        match_ls.tlvs.append(mpls_label)
        match_ls.tlvs.append(mpls_tc)
        return match_ls

    if IP in packet:
        ip = packet[IP]
        ipv4_src = match.ipv4_src(parse_ip(ip.src))
        ipv4_dst = match.ipv4_dst(parse_ip(ip.dst))
        ip_dscp =  match.ip_dscp(ip.tos >> 2) 
        ip_ecn =   match.ip_ecn(ip.tos & 0x03)
        match_ls.tlvs.append(ipv4_src)
        match_ls.tlvs.append(ipv4_dst)
        match_ls.tlvs.append(ip_dscp)
        match_ls.tlvs.append(ip_ecn)
    else:
        return match_ls
    
    if TCP in packet:
        tcp = packet[TCP]
        ip_proto = match.ip_proto(6)
        tcp_src = match.tcp_src(tcp.sport)
        tcp_dst = match.tcp_dst(tcp.dport)
        match_ls.tlvs.append(ip_proto)
        match_ls.tlvs.append(tcp_src)
        match_ls.tlvs.append(tcp_dst)
        return match_ls

    if UDP in packet:
        udp = packet[UDP]
        ip_proto = match.ip_proto(17)
        udp_src = match.tcp_src(udp.sport)
        udp_dst = match.tcp_dst(udp.dport)
        match_ls.tlvs.append(ip_proto)
        match_ls.tlvs.append(udp_src)
        match_ls.tlvs.append(udp_dst)        
        return match_ls

    if ICMP in packet:
        icmp = packet[ICMP]
        ip_proto = match.ip_proto(1)
        icmp_type = match.icmp_type(icmp.type)
        icmp_code = match.icmp_code(icmp.code)
        match_ls.tlvs.append(icmp_type)
        match_ls.tlvs.append(icmp_code)        
        return match_ls

    return match_ls
