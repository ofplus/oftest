
import sys
import logging
from cStringIO import StringIO
#import types
import sys
import pexpect
import re
import oftest
from oftest import config

import of13.cstruct as ofp
import of13.match as oxm_field
import of13.message as message
import of13.action as action
import of13.parse as parse
import of13.instruction as instruction
from packet import Packet
from of13.match_list import match_list
import ofp
import ofp.match as match



try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    from oftest.mpls import *
except ImportError:
    sys.exit("Need to install scapy for packet parsing")

global skipped_test_count
skipped_test_count = 0

# Some useful defines
IP_ETHERTYPE = 0x800
IPV6_ETHERTYPE = 0x86dd
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_MPLS = 0x8847
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11
ICMPV6_PROTOCOL = 0x3a


getBin = lambda x, n: x >= 0 and str(bin(x))[2:].zfill(n)

def printConLog(s):
    """
       Prints the given string onto Console and to Log file.
    """
    logging.debug(s)
    print s

def toPort(portStr, portType):
    """
       Converts the given port string to Tellabs Port Format as below:

       OTU: 0b000HHHHH.HHTTTTTP.PPPP0000.00000000
       OCH-P: 0b001HHHHH.HHTTTTTP.PPPP0000.00000010
       OTS: 0b001HHHHH.HHTTTTTP.PPPP0000.00000000
       Where H-bits are used to encode Shelf, T-bits are used to encode Slot and P-bits are used to encode Port.

       @args

       portStr : String e.g. - 1/12/1 - Shelf/Slot/Port
       portType: String e.g. - OCH - OCH/OTS/OTU
    """

    s = portStr.split('/')
    shelf = int(s[0])
    slot = int(s[1])
    port = int(s[2])

    Sbits = getBin(shelf, 7)
    sbits = getBin(slot, 5)
    pbits = getBin(port, 5)

    if portType =='OTU':
       prefix = '000'
       suffix = '000000000000'
    elif portType == 'OCH':
       prefix = '001'
       suffix = '000000000010'
    elif portType == 'OTS':
       prefix = '001'
       suffix = '000000000000'
    else:
       print "Unsupported PORT Type"

    fullBits = str(prefix) + str(Sbits) + str(sbits) + str(pbits) + str(suffix)
    Port = hex(int(fullBits, 2))[2:].zfill(8)
    return Port


def twosComp(num):

    if num < 0:
       b = getBin(abs(int(num)),16)
       b = ''.join('1' if x == '0' else '0' for x in b)
       b = bin(int(b,2) + int('1',2))
    else:
       b = getBin(int(num),16)
    return b

def toOCHlabel(grid, cs, ID, chNum):
    """
    The label format for an OCh is defined in RFC 6205 Section 3.2 as:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Grid | C.S.  |    Identifier   |              n                |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Where Grid is defined as:
   +----------+---------+
   |   Grid   |  Value  |
   +----------+---------+
   | Reserved |    0    |
   +----------+---------+
   |ITU-T DWDM|    1    |
   +----------+---------+
   |ITU-T CWDM|    2    |
   +----------+---------+
   |Future use|  3 - 7  |
   +----------+---------+

   Channel Spacing (C.S.) is defined as:
   +----------+---------+
   |C.S. (GHz)|  Value  |
   +----------+---------+
   | Reserved |    0    |
   +----------+---------+
   |    100   |    1    |
   +----------+---------+
   |    50    |    2    |
   +----------+---------+
   |    25    |    3    |
   +----------+---------+
   |    12.5  |    4    |
   +----------+---------+
   |Future use|  5 - 15 |
   +----------+---------+

    And N is defined as a two.s-complement integer to take either a positive,
     negative or zero value to compute the frequency of the OCh using the following formula:
      Frequency (THz) = 193.1 THz + n * ChannelSpacing (THz)

    Example:
     A label for OCh Number 1 (191.7THz) on a 50Ghz-spaced (i.e. 88-channel) OTS is:
                   0b00100100.00000000.11111111.11100100 (0x2400:FFE4)

    """

    # 88-Channel table

    ch_to_freq = { 1:191.7, 2:191.8, 3:191.9, 4:192.0, 5:192.1, 6:192.2, 7:192.3, 8:192.4, \
                   9:192.5, 10:192.6, 11:192.7, 12:192.8, 13:192.9, 14:193.0, 15:193.1, 16:193.2, \
                   17:193.3, 18:193.4, 19:193.5, 20:193.6, 21:193.7, 22:193.8, 23:193.9, 24:194.0, \
                   25:194.1, 26:194.2, 27:194.3, 28:194.4, 29:194.5, 30:194.6, 31:194.7, 32:194.8, \
                   33:194.9, 34:195.0, 35:195.1, 36:195.2, 37:195.3, 38:195.4, 39:195.5, 40:195.6, \
                   41:195.7, 42:195.8, 43:195.9, 44:196.0, 45:191.75, 46:191.85, 47:191.95, 48:192.05, \
                   49:192.15, 50:192.25, 51:192.35, 52:192.45, 53:192.55, 54:192.65, 55:192.75, 56:192.85, \
                   57:192.95, 58:193.05, 59:193.15, 60:193.25, 61:193.35, 62:193.45, 63:193.55, 64:193.65, \
                   65:193.75, 66:193.85, 67:193.95, 68:194.05, 69:194.15, 70:194.25, 71:194.35, 72:194.45, \
                   73:194.55, 74:194.65, 75:194.75, 76:194.85, 77:194.95, 78:195.05, 79:195.15, 80:195.25, \
                   81:195.35, 82:195.45, 83:195.55, 84:195.65, 85:195.75, 86:195.85, 87:195.95, 88:196.05 \
                }


    # Channel Spacing table
    cs_to_freq = { 1: .10, 2: .05, 3: .025}

    n = (ch_to_freq[chNum] - 193.1) / cs_to_freq[cs]
    bn = twosComp(n)
    fullBits = str(getBin(grid,3)) + str(getBin(cs,4)) + str(getBin(ID,9)) + str(getBin(int(bn,2),16))
    label = hex(int(fullBits, 2))[2:].zfill(8)
    return label

def toODUlabel(ts,tpn,blen,tslots):
    """
    The label format is not limited to 4-bytes.  In draft-ietf-ccamp-gmpls-signaling-g709v3, the label format for an ODUx is defined in Section 6.1 as:
    0                   1                   2                   3 
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |         TPN           |   Reserved    |        Length         | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   ~                   Bit Map          ......                     ~ 
   ~              ......                   |     Padding Bits      ~ 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    With the bit map indicating the tributary slots to be used for the signal being established.  The number of Bits in the Bit-Map is dependent on the type of interface being configured (e.g. an OTU2 with 1.25G TS has 8 TS, an OTU4 with 1.25G TS has 80 TS).  The label has padding at the end of it to make it a multiple of 4 bytes.  The TPN (Tributary Port Number) provides a unique identifier for link connection in the scope of the trail.
 
    Example:
    A label for a ODU1 using TS 1,2,3,4 and TPN=2 would be 0b00000000.00100000.00000000.00001000.11110000.00000000.00000000.00000000 (0x0020:0008:F000:0000)
    """
    reserved = 0
    word1 = str(getBin(tpn,12)) + str(getBin(reserved,8)) + str(getBin(blen,12))
    padlen = 32 - blen
    bmap = ''
    tslots = list(tslots)
    for i in range(1, blen+1):
       if i in tslots:
          bit = 1
       else:
          bit = 0
       bmap = bmap + str(bit)
    bmap = bmap + str(0)[2:].zfill(padlen)
    label = word1 + bmap
    label = hex(int(label, 2))[2:].zfill(16)
    return label


def getflowInputs1():
    """
    Util function to get User inputs for Various Flow Mod Match and Action
    Fields.

    Returns a dictionary of match and action field objects.
    with format flowInps['key'] = <match or action obj>,
    where,
    key is m_inport, a_inport, m_swcapenctype, m_sigtype, m_label, a_outport, m_outport, a_label,
    """

    inpDict = {} 
    print
    print "  Available Match Fields : 1. IN_PORT  2. SWCAPENCTYPE 3.SIGTYPE 4. LABEL"
    print "  Available Action Fields: 1. OUT_PORT 2. LABEL"
    print
    mf = raw_input("  Enter the Match Fields required(e.g. 1,2,3,4)[All]  :")
    mf = map(int, mf.split(',')) if mf != '' else [1,2,3,4]
    print


    for m in mf:
       if m == 1:
          value1 = raw_input("  INPUT_PORT [0x204A1002]         = ")
          value1 = int(value1,16) if value1 != '' else 0x204A1002
          m_inport = match.in_port(value1)
          a_inport = ofp.action.output(port=value1)
          inpDict['m_inport'] = m_inport
          inpDict['a_inport'] = a_inport
       elif m == 2:
          value1 = raw_input("  Switching Capability [150]      = ")
          value1 = int(value1) if value1 != '' else 150
          value2 = raw_input("  Encoding Type [8]               = ")
          value2 = int(value2) if value2 != '' else 8
          m_swcapenctype = match.swcapenctype(value1,value2)
          inpDict['m_swcapenctype'] = m_swcapenctype
       elif m == 3:
          value1 = raw_input("  Signal Type [0]                 = ")
          value1 = int(value1) if value1 != '' else 0
          m_sigtype = match.sigtype(value1)
          inpDict['m_sigtype'] = m_sigtype
       elif m == 4:
          value1 = raw_input("  Label [0x26001034]              = ")
          value1 = int(value1,16) if value1 != '' else 0x26001034
          m_label = match.label(value1)
          inpDict['m_label'] = m_label

    print
    print
    af = raw_input("  Enter the Action Fields required(e.g. 1,2) [All]  :")
    af = map(int, af.split(',')) if af != '' else [1,2]
    print
    for a in af:
      if a == 1:
         prt = raw_input("  OUTPUT_PORT [0x204C1002]        = ")
         prt = int(prt,16) if prt != '' else 0x204C1002
         a_outport = ofp.action.output(port=prt)
         m_outport = match.in_port(prt)
         inpDict['a_outport'] = a_outport
         inpDict['m_outport'] = m_outport

      elif a == 2:
         lbl = raw_input("  Label [0x26001034]              = ")
         lbl = int(lbl,16) if lbl != '' else 0x26001034
         a_label = ofp.action.experimenter(action=3, payload=lbl)
         inpDict['a_label'] = a_label

    return inpDict



def getflowInputs(self):
    """
    Util function to get User inputs for Various Flow Mod Match and Action
    Fields.

    Returns a dictionary of match and action field objects.
    with format flowInps['key'] = <match or action obj>,
    where,
    key is m_inport, a_inport, m_swcapenctype, m_sigtype, m_label, a_outport, m_outport, a_label,
    """

    inpDict = {} 
    print
    print "  Available Match Fields : 1. IN_PORT  2. SWCAPENCTYPE 3.SIGTYPE 4. LABEL"
    print "  Available Action Fields: 1. OUT_PORT 2. LABEL"
    print
    mf = raw_input("  Enter the Match Fields required(e.g. 1,2,3,4)[All]  :")
    mf = map(int, mf.split(',')) if mf != '' else [1,2,3,4]
    print


    for m in mf:
       if m == 1:
          print "  Enter Details for IN_PORT:"
          instr = "     Shelf/Slot/Port [" + str(self.config["port-no1"]) + "]      = "
          port = raw_input(instr)
          port = port if port != '' else self.config["port-no1"]
          ptype = raw_input("     Type [OTU, OCH, OTS]         = ")
          ptype = ptype if ptype != '' else self.config["port-type1"]
          if port == '0/0/0':
             value1 = 0xFFFFFFFF
          else:
             value1 = int(toPort(port, ptype),16)
          inpDict['m_inport'] = match.in_port(value1)
          inpDict['a_inport'] = ofp.action.output(port=value1)
       elif m == 2:
          value1 = raw_input("  Switching Capability [150]      = ")
          value1 = int(value1) if value1 != '' else 150
          value2 = raw_input("  Encoding Type [8]               = ")
          value2 = int(value2) if value2 != '' else 8
          m_swcapenctype = match.swcapenctype(value1,value2)
          inpDict['m_swcapenctype'] = m_swcapenctype
       elif m == 3:
          value1 = raw_input("  Signal Type [0]                 = ")
          value1 = int(value1) if value1 != '' else 0
          m_sigtype = match.sigtype(value1)
          inpDict['m_sigtype'] = m_sigtype
       elif m == 4:
          print
          print "  Port Type is given as", ptype
          if ptype == 'OCH' or ptype == 'OTS':
              print "  Enter the Grid, C.S, Identifier, Channel Number for LABEL:"
              grid = raw_input("  Grid [0 to 2]                   = ")
              grid = int(grid) if grid != '' else 1
              cs = raw_input("  C.S. [0 to 4]                   = ")
              cs = int(cs) if cs != '' else 2
              ID = raw_input("  Identifier [0]                  = ")
              ID = int(ID) if ID != '' else 0
              cnum = raw_input("  Channel Number [1 to 88]        = ")
              cnum = int(cnum) if cnum != '' else 1
              value1 = int(toOCHlabel(grid,cs,ID,cnum), 16)
              inpDict['m_label'] = match.label(value1)
          elif ptype == 'OTU':
              lt = raw_input("    Enter Label Type (1. ODU -HO  2. Non ODU -HO):")
              lt = int(lt) if lt != '' else 1
              if lt == 1:
                 value1 = 0
                 inpDict['m_label'] = match.label(value1)
                 inpDict['a_label_msg2'] = ofp.action.experimenter(action=3, payload=value1)
                 print "      Label value set as Zero"
              elif lt == 2:
                 print "      Enter the TS Size, TPN, bitlen and TribSlots:"
                 ts = raw_input("        TS Size [1 for 1.25G, 2 for 2.5G]        = ")
                 ts = int(ts) if ts != '' else 1
                 tpn = raw_input("        TPN [0 to 16]                            = ")
                 tpn = int(tpn) if tpn != '' else 0
                 blen = raw_input("        Bit Length [0 to 32]                     = ")
                 blen = int(blen) if blen != '' else 0
                 tslots= tuple(map(int,raw_input("        Tribslots [1 to 32, comma-separated]     = ").split(',')))
                 tslots = tslots if tslots != '' else 1
                 value1 = int(toODUlabel(ts,tpn,blen,tslots), 16)
                 inpDict['m_label'] = match.non_ho_odu_label(value1)
                 inpDict['a_label_msg2'] = ofp.action.experimenter(action=3, payload=value1, len=24)

    print
    print
    af = raw_input("  Enter the Action Fields required(e.g. 1,2) [All]  :")
    af = map(int, af.split(',')) if af != '' else [1,2]
    print
    for a in af:
      if a == 1:
         print "  Enter Details for OUT_PORT:"
         instr = "     Shelf/Slot/Port [" + str(self.config["port-no2"]) + "]       = "
         port = raw_input(instr)
         port = port if port != '' else self.config["port-no2"]
         ptype = raw_input("     Type [OTU, OCH, OTS]          = ")
         ptype = ptype if ptype != '' else self.config["port-type2"]
         if port == '0/0/0':
             value1 = 0xFFFFFFFF
         else:
            value1 = int(toPort(port, ptype), 16)
         inpDict['a_outport'] = ofp.action.output(port=value1)
         inpDict['m_outport'] = match.in_port(value1)
      elif a == 2:
          print
          print "  Port Type is given as", ptype
          if ptype == 'OCH' or ptype == 'OTS':
              print "  Enter the Grid, C.S, Identifier, Channel Number for LABEL:"
              grid = raw_input("  Grid [0 to 2]                   = ")
              grid = int(grid) if grid != '' else 1
              cs = raw_input("  C.S. [0 to 4]                   = ")
              cs = int(cs) if cs != '' else 2
              ID = raw_input("  Identifier [0]                  = ")
              ID = int(ID) if ID != '' else 0
              cnum = raw_input("  Channel Number [1 to 88]        = ")
              cnum = int(cnum) if cnum != '' else 1
              value1 = int(toOCHlabel(grid,cs,ID,cnum), 16)
              inpDict['a_label'] = ofp.action.experimenter(action=3, payload=value1)
          elif ptype == 'OTU':
              lt = raw_input("    Enter Label Type (1. ODU -HO  2. Non ODU -HO):")
              lt = int(lt) if lt != '' else 1
              if lt == 1:
                 value1 = 0
                 inpDict['a_label'] = ofp.action.experimenter(action=3, payload=value1)
                 inpDict['m_label_msg2'] = match.non_ho_odu_label(value1)
                 print "      Label value set as Zero"
              elif lt == 2:
                 print "      Enter the TS Size, TPN, bitlen and TribSlots:"
                 ts = raw_input("        TS Size [1 for 1.25G, 2 for 2.5G]        = ")
                 ts = int(ts) if ts != '' else 1
                 tpn = raw_input("        TPN [0 to 16]                            = ")
                 tpn = int(tpn) if tpn != '' else 0
                 blen = raw_input("        Bit Length [0 to 32]                     = ")
                 blen = int(blen) if blen != '' else 0
                 tslots= tuple(map(int,raw_input("        Tribslots [1 to 32, comma-separated]     = ").split(',')))
                 tslots = tslots if tslots != '' else 1
                 value1 = int(toODUlabel(ts,tpn,blen,tslots), 16)
                 inpDict['a_label'] = ofp.action.experimenter(action=3, payload=value1, len=24)
                 inpDict['m_label_msg2'] = match.non_ho_odu_label(value1)

    return inpDict

def clear_switch(parent, port_list, logger):
    """
    Clear the switch configuration

    @param parent Object implementing controller and assert equal
    @param logger Logging object
    """
    parent.assertTrue(len(port_list) > 2, "Not enough ports for test")
    for port in port_list:
        clear_port_config(parent, port, logger)
    initialize_table_config(parent.controller, logger)
    delete_all_flows(parent.controller, logger)
    delete_all_groups(parent.controller, logger)

    return port_list

def initialize_table_config(ctrl, logger):
    """
    Initialize all table configs to default setting ("CONTROLLER")
    @param ctrl The controller object for the test
    """
    logger.info("Initializing all table configs")
    request = message.table_mod()  
    request.config = ofp.OFPTC_TABLE_MISS_CONTROLLER
    rv = 0
    for table_id in [0, 1, 2, 3, 4, 5, 6, 7]:
        request.table_id = table_id
        rv |= ctrl.message_send(request)
    return rv

def delete_all_flows(ctrl, logger):
    """
    Delete all flows on the switch
    @param ctrl The controller object for the test
    @param logger Logging object
    """

    logger.info("Deleting all flows")
    #DEFAULT_TABLE_COUNT = 4
    return delete_all_flows_one_table(ctrl, logger, table_id=0xff)

def delete_all_flows_one_table(ctrl, logger, table_id=0):
    """
    Delete all flows on a table
    @param ctrl The controller object for the test
    @param logger Logging object
    @param table_id Table ID
    """
    logger.info("Deleting all flows on table ID: " + str(table_id))
    msg = message.flow_mod()
    msg.out_port = ofp.OFPP_ANY
    msg.out_group = ofp.OFPG_ANY
    msg.command = ofp.OFPFC_DELETE
    msg.buffer_id = 0xffffffff
    msg.table_id = table_id
    logger.debug(msg.show())

    return ctrl.message_send(msg)

def delete_all_groups(ctrl, logger):
    """
    Delete all groups on the switch
    @param ctrl The controller object for the test
    @param logger Logging object
    """
    
    logger.info("Deleting all groups")
    msg = message.group_mod()
    msg.group_id = ofp.OFPG_ALL
    msg.command = ofp.OFPGC_DELETE
    logger.debug(msg.show())
    return ctrl.message_send(msg)

def clear_port_config(parent, port, logger):
    """
    Clear the port configuration 

    @param parent Object implementing controller and assert equal
    @param logger Logging object
    """
    rv = port_config_set(parent.controller, port,
                         0, 0, logger)
    parent.assertEqual(rv, 0, "Failed to reset port config")

def simple_tcp_packet(dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      vlan_tags=[],  # {type,vid,pcp,cfi}  TODO type
                      mpls_tags=[],  # {type,label,tc,ttl} TODO type 
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=64,
                      tcp_sport=1234,
                      tcp_dport=80,
                      payload_len = 46):
    pkt = Ether(dst=dl_dst, src=dl_src)

    vlans_num = 0
    while len(vlan_tags):
        tag = vlan_tags.pop(0)
        dot1q = Dot1Q()
        if 'vid' in tag:
            dot1q.vlan = tag['vid']
        if 'pcp' in tag:
            dot1q.prio = tag['pcp']
        if 'cfi' in tag:
            dot1q.id = tag['cfi']
        pkt = pkt / dot1q 
        if 'type' in tag:
            if vlans_num == 0:
                pkt[Ether].setfieldval('type', tag['type'])
            else:
                pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        vlans_num+=1

    mplss_num = 0
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        pkt = pkt / mpls
        if 'type' in tag:
            if mplss_num == 0:
                if vlans_num == 0:
                    pkt[Ether].setfieldval('type', tag['type'])
                else:
                    pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        mplss_num+=1

    pkt = pkt / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl) \
              / TCP(sport=tcp_sport, dport=tcp_dport)
    
    pkt = pkt / ("D" * payload_len)

    return pkt

def simple_icmp_packet(dl_dst='00:01:02:03:04:05',
                       dl_src='00:06:07:08:09:0a',
                       vlan_tags=[],  # {type,vid,pcp,cfi}  TODO type
                       mpls_tags=[],  # {type,label,tc,ttl} TODO type 
                       ip_src='192.168.0.1',
                       ip_dst='192.168.0.2',
                       ip_tos=0,
                       ip_ttl=64,
                       icmp_type=8, # ICMP_ECHO_REQUEST
                       icmp_code=0,
                       payload_len=0):

    #TODO simple_ip_packet
    pkt = Ether(dst=dl_dst, src=dl_src)

    vlans_num = 0
    while len(vlan_tags):
        tag = vlan_tags.pop(0)
        dot1q = Dot1Q()
        if 'vid' in tag:
            dot1q.vlan = tag['vid']
        if 'pcp' in tag:
            dot1q.prio = tag['pcp']
        if 'cfi' in tag:
            dot1q.id = tag['cfi']
        pkt = pkt / dot1q 
        if 'type' in tag:
            if vlans_num == 0:
                pkt[Ether].setfieldval('type', tag['type'])
            else:
                pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        vlans_num+=1

    mplss_num = 0
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        pkt = pkt / mpls
        if 'type' in tag:
            if mplss_num == 0:
                if vlans_num == 0:
                    pkt[Ether].setfieldval('type', tag['type'])
                else:
                    pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        mplss_num+=1

    pkt = pkt / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl) \
              / ICMP(type=icmp_type, code=icmp_code)

    pkt = pkt / ("D" * payload_len)

    return pkt

def simple_ipv6_packet(pktlen=100, 
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_tos=0,
                      tcp_sport=0,
                      tcp_dport=0, 
                      EH = False, 
                      EHpkt = IPv6ExtHdrDestOpt()
                      ):

    """
    Return a simple IPv6 packet 

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    """
    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            IPv6(src=ip_src, dst=ip_dst)

    else:
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            IPv6(src=ip_src, dst=ip_dst)

    # Add IPv6 Extension Headers 
    if EH:
        pkt = pkt / EHpkt

    if (tcp_sport >0 and tcp_dport >0):
        pkt = pkt / TCP(sport=tcp_sport, dport=tcp_dport)

    if pktlen > len(pkt) :
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_icmpv6_packet(pktlen=100, 
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_tos=0,
                      tcp_sport=0,
                      tcp_dport=0, 
                      EH = False, 
                      EHpkt = IPv6ExtHdrDestOpt(),
                      route_adv = False,
                      sll_enabled = False
                      ):

    """
    Return a simple dataplane ICMPv6 packet 

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port
    
    """
    if (dl_vlan_enable):
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            IPv6(src=ip_src, dst=ip_dst)

    else:
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            IPv6(src=ip_src, dst=ip_dst)
            
            
    # Add IPv6 Extension Headers 
    if EH:
        pkt = pkt / EHpkt

    if route_adv:
        pkt = pkt/ \
        ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L, routerlifetime=1800, P=0L, retranstimer=0, prf=0L, res=0L)/ \
        ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L, len=4, prefix='fd00:141:64:1::', R=0L, validlifetime=1814400, prefixlen=64, preferredlifetime=604800, type=3)
        if sll_enabled :
            pkt = pkt/ \
            ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='66:6f:df:2d:7c:9c')
    else :
        pkt = pkt/ \
            ICMPv6EchoRequest()
    if (tcp_sport >0 and tcp_dport >0):
        pkt = pkt / TCP(sport=tcp_sport, dport=tcp_dport)

    if pktlen > len(pkt) :
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt


def do_barrier(ctrl):
    b = message.barrier_request()
    ctrl.transact(b)


def port_config_get(controller, port_no, logger):
    """
    Get a port's configuration

    Gets the switch feature configuration and grabs one port's
    configuration

    @returns (hwaddr, config, advert) The hwaddress, configuration and
    advertised values
    """
    request = message.features_request()
    reply, _ = controller.transact(request, timeout=2)
    if reply is None:
        logger.warn("Get feature request failed")
        return None, None, None
    logger.debug(reply.show())
    for idx in range(len(reply.ports)):
        if reply.ports[idx].port_no == port_no:
            return (reply.ports[idx].hw_addr, reply.ports[idx].config,
                    reply.ports[idx].advertised)
    
    logger.warn("Did not find port number for port config")
    return None, None, None

def port_config_set(controller, port_no, config, mask, logger):
    """
    Set the port configuration according the given parameters

    Gets the switch feature configuration and updates one port's
    configuration value according to config and mask
    """
    logger.info("Setting port " + str(port_no) + " to config " + str(config))
    request = message.features_request()
    reply, _ = controller.transact(request, timeout=2)
    if reply is None:
        return -1
    logger.debug(reply.show())
    for idx in range(len(reply.ports)):
        if reply.ports[idx].port_no == port_no:
            break
    if idx >= len(reply.ports):
        return -1
    mod = message.port_mod()
    mod.port_no = port_no
    mod.hw_addr = reply.ports[idx].hw_addr
    mod.config = config
    mod.mask = mask
    mod.advertise = reply.ports[idx].advertised
    rv = controller.message_send(mod)
    return rv

def receive_pkt_check(dataplane, pkt, yes_ports, no_ports, assert_if, logger):
    """
    Check for proper receive packets across all ports
    @param dataplane The dataplane object
    @param pkt Expected packet; may be None if yes_ports is empty
    @param yes_ports Set or list of ports that should recieve packet
    @param no_ports Set or list of ports that should not receive packet
    @param assert_if Object that implements assertXXX
    """
    for ofport in yes_ports:
        logger.debug("Checking for pkt on port " + str(ofport))
        (_, rcv_pkt, _) = dataplane.poll(
            port_number=ofport, timeout=1)
        assert_if.assertTrue(rcv_pkt is not None, 
                             "Did not receive pkt on " + str(ofport))
        assert_if.assertEqual(str(pkt), str(rcv_pkt),
                              "Response packet does not match send packet " +
                              "on port " + str(ofport))

    for ofport in no_ports:
        logger.debug("Negative check for pkt on port " + str(ofport))
        (_, rcv_pkt, _) = dataplane.poll(
            port_number=ofport, timeout=1)
        assert_if.assertTrue(rcv_pkt is None, 
                             "Unexpected pkt on port " + str(ofport))


def pkt_verify(parent, rcv_pkt, exp_pkt):
    if str(exp_pkt) != str(rcv_pkt):
        logging.error("ERROR: Packet match failed.")
        logging.debug("Expected (" + str(len(exp_pkt)) + ")")
        logging.debug(str(exp_pkt).encode('hex'))
        sys.stdout = tmpout = StringIO()
        exp_pkt.show()
        sys.stdout = sys.__stdout__
        logging.debug(tmpout.getvalue())
        logging.debug("Received (" + str(len(rcv_pkt)) + ")")
        logging.debug(str(rcv_pkt).encode('hex'))
        sys.stdout = tmpout = StringIO()
        Ether(rcv_pkt).show()
        sys.stdout = sys.__stdout__
        logging.debug(tmpout.getvalue())
    parent.assertEqual(str(exp_pkt), str(rcv_pkt),
                       "Packet match error")
    
    return rcv_pkt

def receive_pkt_verify(parent, egr_port, exp_pkt):
    """
    Receive a packet and verify it matches an expected value

    parent must implement dataplane, assertTrue and assertEqual
    """
    (rcv_port, rcv_pkt, _) = parent.dataplane.poll(port_number=egr_port,
                                                          timeout=1)

    if exp_pkt is None:
        if rcv_pkt is None:
            return None
        else:
            logging.error("ERROR: Received unexpected packet from " + str(egr_port));
            return rcv_pkt

    if rcv_pkt is None:
        logging.error("ERROR: No packet received from " + str(egr_port))

    parent.assertTrue(rcv_pkt is not None,
                      "Did not receive packet port " + str(egr_port))
    logging.debug("Packet len " + str(len(rcv_pkt)) + " in on " + 
                    str(rcv_port))

    return pkt_verify(parent, rcv_pkt, exp_pkt)

def packetin_verify(parent, exp_pkt):
    """
    Receive packet_in and verify it matches an expected value
    """
    (response, _) = parent.controller.poll(ofp.OFPT_PACKET_IN, 2)

    parent.assertTrue(response is not None, 'Packet in message not received')
    if str(exp_pkt) != response.data:
        logging.debug("pkt  len " + str(len(str(exp_pkt))) + ": "
                            + str(exp_pkt).encode('hex'))
        logging.debug("resp len " + str(len(str(response.data))) + ": "
                            + str(response.data).encode('hex'))
    parent.assertEqual(str(exp_pkt), response.data,
                     'PACKET_IN packet does not match send packet')

def match_verify(parent, req_match, res_match):
    """
    Verify flow matches agree; if they disagree, report where

    parent must implement assertEqual
    Use str() to ensure content is compared and not pointers
    """

    parent.assertEqual(req_match.wildcards, res_match.wildcards,
                       'Match failed: wildcards: ' + hex(req_match.wildcards) +
                       " != " + hex(res_match.wildcards))
    parent.assertEqual(req_match.in_port, res_match.in_port,
                       'Match failed: in_port: ' + str(req_match.in_port) +
                       " != " + str(res_match.in_port))
    parent.assertEqual(str(req_match.dl_src), str(res_match.dl_src),
                       'Match failed: dl_src: ' + str(req_match.dl_src) +
                       " != " + str(res_match.dl_src))
    parent.assertEqual(str(req_match.dl_dst), str(res_match.dl_dst),
                       'Match failed: dl_dst: ' + str(req_match.dl_dst) +
                       " != " + str(res_match.dl_dst))
    parent.assertEqual(req_match.dl_vlan, res_match.dl_vlan,
                       'Match failed: dl_vlan: ' + str(req_match.dl_vlan) +
                       " != " + str(res_match.dl_vlan))
    parent.assertEqual(req_match.dl_vlan_pcp, res_match.dl_vlan_pcp,
                       'Match failed: dl_vlan_pcp: ' + 
                       str(req_match.dl_vlan_pcp) + " != " + 
                       str(res_match.dl_vlan_pcp))
    parent.assertEqual(req_match.dl_type, res_match.dl_type,
                       'Match failed: dl_type: ' + str(req_match.dl_type) +
                       " != " + str(res_match.dl_type))

    if (not(req_match.wildcards & ofp.OFPFW_DL_TYPE)
        and (req_match.dl_type == IP_ETHERTYPE)):
        parent.assertEqual(req_match.nw_tos, res_match.nw_tos,
                           'Match failed: nw_tos: ' + str(req_match.nw_tos) +
                           " != " + str(res_match.nw_tos))
        parent.assertEqual(req_match.nw_proto, res_match.nw_proto,
                           'Match failed: nw_proto: ' + str(req_match.nw_proto) +
                           " != " + str(res_match.nw_proto))
        parent.assertEqual(req_match.nw_src, res_match.nw_src,
                           'Match failed: nw_src: ' + str(req_match.nw_src) +
                           " != " + str(res_match.nw_src))
        parent.assertEqual(req_match.nw_dst, res_match.nw_dst,
                           'Match failed: nw_dst: ' + str(req_match.nw_dst) +
                           " != " + str(res_match.nw_dst))

        if (not(req_match.wildcards & ofp.OFPFW_NW_PROTO)
            and ((req_match.nw_proto == TCP_PROTOCOL)
                 or (req_match.nw_proto == UDP_PROTOCOL))):
            parent.assertEqual(req_match.tp_src, res_match.tp_src,
                               'Match failed: tp_src: ' + 
                               str(req_match.tp_src) +
                               " != " + str(res_match.tp_src))
            parent.assertEqual(req_match.tp_dst, res_match.tp_dst,
                               'Match failed: tp_dst: ' + 
                               str(req_match.tp_dst) +
                               " != " + str(res_match.tp_dst))

def flow_removed_verify(parent, request=None, pkt_count=-1, byte_count=-1):
    """
    Receive a flow removed msg and verify it matches expected

    @params parent Must implement controller, assertEqual
    @param pkt_count If >= 0, verify packet count
    @param byte_count If >= 0, verify byte count
    """
    (response, _) = parent.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
    parent.assertTrue(response is not None, 'No flow removed message received')

    if request is None:
        return

    parent.assertEqual(request.cookie, response.cookie,
                       "Flow removed cookie error: " +
                       hex(request.cookie) + " != " + hex(response.cookie))

    req_match = request.match
    res_match = response.match
    verifyMatchField(req_match, res_match)

    if (req_match.wildcards != 0):
        parent.assertEqual(request.priority, response.priority,
                           'Flow remove prio mismatch: ' + 
                           str(request.priority) + " != " + 
                           str(response.priority))
        parent.assertEqual(response.reason, ofp.OFPRR_HARD_TIMEOUT,
                           'Flow remove reason is not HARD TIMEOUT:' +
                           str(response.reason))
        if pkt_count >= 0:
            parent.assertEqual(response.packet_count, pkt_count,
                               'Flow removed failed, packet count: ' + 
                               str(response.packet_count) + " != " +
                               str(pkt_count))
        if byte_count >= 0:
            parent.assertEqual(response.byte_count, byte_count,
                               'Flow removed failed, byte count: ' + 
                               str(response.byte_count) + " != " + 
                               str(byte_count))
def flow_msg_create(parent, pkt, ing_port=0, match_fields=None, instruction_list=None, 
                    action_list=None,wildcards=0, egr_port=None, 
                    egr_queue=None, table_id=0, check_expire=False):
    """
    Multi-purpose flow_mod creation utility

    Match on packet with given wildcards.  
    See flow_match_test for other parameter descriptoins
   
    if egr_queue is set
             append an out_queue action to egr_queue to the actions_list
    else if egr_port is set:  
             append an output action to egr_port to the actions_list
    if the instruction_list is empty, 
        append an APPLY instruction to it
    Add the action_list to the first write or apply instruction
    
    @param egr_queue if not None, make the output an enqueue action
    @param table_id Table ID for writing a flow_mod
    """

    if match_fields is None:
        match_fields = parse.packet_to_flow_match(pkt)
    parent.assertTrue(match_fields is not None, "Flow match from pkt failed")
    in_port = oxm_field.in_port(ing_port)
    match_fields.add(in_port) 
    request = message.flow_mod()
    request.match_fields = match_fields
    request.buffer_id = 0xffffffff
    request.table_id = table_id
    
    if check_expire:
        request.flags |= ofp.OFPFF_SEND_FLOW_REM
        request.hard_timeout = 1    
    
    if action_list is None:
        action_list = []
    if instruction_list is None:
        instruction_list = []
    
    # Set up output/enqueue action if directed
    if egr_queue is not None:
        parent.assertTrue(egr_port is not None, "Egress port not set")
        act = action.set_queue()
        act.port = egr_port
        act.queue_id = egr_queue
        action_list.append(act)
    elif egr_port is not None:
        act = action.output()
        act.port = egr_port
        action_list.append(act)
        
    inst = None
    if len(instruction_list) == 0: 
        inst = instruction.instruction_apply_actions()
        instruction_list.append(inst)
    else:
        for inst in instruction_list:
            if (inst.type == ofp.OFPIT_WRITE_ACTIONS or
                inst.type == ofp.OFPIT_APPLY_ACTIONS):
                break

    # add all the actions to the last inst
    for act in action_list:
        logging.debug("Adding action " + act.show())
        rv = inst.actions.add(act)
        parent.assertTrue(rv, "Could not add action" + act.show())
    # NOTE that the inst has already been added to the flow_mod

    # add all the instrutions to the flow_mod
    for i in instruction_list: 
        logging.debug("Adding instruction " + inst.show())
        rv = request.instructions.add(i)
        parent.assertTrue(rv, "Could not add instruction " + i.show())

 
    logging.debug(request.show())
    return request

def flow_msg_install(parent, request, clear_table=True):
    """
    Install a flow mod message in the switch

    @param parent Must implement controller, assertEqual, assertTrue
    @param request The request, all set to go
    @param clear_table If true, clear the flow table before installing
    """
    if clear_table:
        logging.debug("Clear flow table")
        if request.table_id:
            table_id = request.table_id
        else:
            table_id = 0
        rc = delete_all_flows_one_table(parent.controller,
                                        logging,
                                        table_id)
        parent.assertEqual(rc, 0, "Failed to delete all flows on table: "
                           + str(table_id))
        do_barrier(parent.controller)

    logging.debug("Insert flow::\n%s" % request.show())
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error installing flow mod")
    do_barrier(parent.controller)

def error_verify(parent, exp_type, exp_code):
    """
    Receive an error msg and verify if it is as expected

    @param parent Must implement controller, assertEqual
    @param exp_type Expected error type
    @param exp_code Expected error code
    """
    (response, raw) = parent.controller.poll(ofp.OFPT_ERROR, 2)
    parent.assertTrue(response is not None, 'No error message received')

    if (exp_type is None) or (exp_code is None):
        logging.debug("Parametrs are not sufficient")
        return

    parent.assertEqual(exp_type, response.type,
                       'Error message type mismatch: ' +
                       str(exp_type) + " != " +
                       str(response.type))
    parent.assertEqual(exp_code, response.code,
                       'Error message code mismatch: ' +
                       str(exp_code) + " != " +
                       str(response.code))

def flow_match_test_port_pair(parent, ing_port, egr_port, match=None, 
                              wildcards=0, mask=None,
                              dl_vlan=-1, pkt=None, exp_pkt=None,
                              apply_action_list=None, check_expire=False):
    """
    Flow match test on single TCP packet

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test for parameter descriptions
    """

    logging.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    logging.debug("  WC: " + hex(wildcards) + " vlan: " + str(dl_vlan) +
                    " expire: " + str(check_expire))
    if pkt is None:
        if dl_vlan >= 0:
            pkt = simple_tcp_packet(vlan_tags=[{'vid': dl_vlan}])
        else:
            pkt = simple_tcp_packet()

    match = parse.packet_to_flow_match(pkt)
    parent.assertTrue(match is not None, "Flow match from pkt failed")

    if mask is not None:
        match.dl_src_mask = mask['dl_src']
        match.dl_dst_mask = mask['dl_dst']
        match.nw_src_mask = mask['nw_src']
        match.nw_dst_mask = mask['nw_dst']
        #Set unmatching values on corresponding match fields
        for i in range(ofp.OFP_ETH_ALEN):
            match.dl_src[i] = match.dl_src[i] ^ match.dl_src_mask[i]
            match.dl_dst[i] = match.dl_dst[i] ^ match.dl_dst_mask[i]
        match.nw_src = match.nw_src ^ match.nw_src_mask
        match.nw_dst = match.nw_dst ^ match.nw_dst_mask

    request = flow_msg_create(parent, pkt, ing_port=ing_port, 
                              match=match,
                              wildcards=wildcards, egr_port=egr_port,
                              action_list=apply_action_list)

    flow_msg_install(parent, request)

    logging.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    parent.dataplane.send(ing_port, str(pkt))

    if exp_pkt is None:
        exp_pkt = pkt
    receive_pkt_verify(parent, egr_port, exp_pkt)

    if check_expire:
        #@todo Not all HW supports both pkt and byte counters
        flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))
def flow_match_test(parent, port_map, match=None, wildcards=0,
                    mask=None, dl_vlan=-1, pkt=None,
                    exp_pkt=None, apply_action_list=None,
                    check_expire=False,  max_test=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param pkt If not None, use this packet for ingress
    @param match If not None, use this value in flow_mod
    @param wildcards For flow match entry
    @param mask DL/NW address bit masks as a dictionary. If set, it is tested
    against the corresponding match fields with the opposite values
    @param dl_vlan If not -1, and pkt is None, create a pkt w/ VLAN tag
    @param exp_pkt If not None, use this as the expected output pkt; els use pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair(parent, ingress_port, egress_port, 
                                      match=match, wildcards=wildcards,
                                      dl_vlan=dl_vlan, mask=mask,
                                      pkt=pkt, exp_pkt=exp_pkt,
                                      apply_action_list=apply_action_list,
                                      check_expire=check_expire)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                logging.info("Ran " + str(test_count) + " tests; exiting")
                return

def flow_match_test_port_pair_vlan(parent, ing_port, egr_port, wildcards=0,
                                   dl_vlan=ofp.OFPVID_NONE, dl_vlan_pcp=0,
                                   dl_vlan_type=ETHERTYPE_VLAN,
                                   dl_vlan_int=-1, dl_vlan_pcp_int=0,
                                   vid_match=ofp.OFPVID_NONE, pcp_match=0,
                                   exp_vid=-1, exp_pcp=0,
                                   exp_vlan_type=ETHERTYPE_VLAN,
                                   match_exp=True,
                                   add_tag_exp=False,
                                   exp_msg=ofp.OFPT_FLOW_REMOVED,
                                   exp_msg_type=0, exp_msg_code=0,
                                   pkt=None, exp_pkt=None,
                                   action_list=None, check_expire=False):
    """
    Flow match test for various vlan matching patterns on single TCP packet

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test_vlan for parameter descriptions
    """
    logging.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    logging.debug("  WC: " + hex(wildcards) + " vlan: " + str(dl_vlan) +
                    " expire: " + str(check_expire))
    if pkt is None:
        if dl_vlan >= 0 and dl_vlan != ofp.OFPVID_NONE:
            if dl_vlan_int >= 0 and dl_vlan_int != ofp.OFPVID_NONE:
                pkt = simple_tcp_packet(
                        vlan_tags=[{'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp},
                                   {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
            else:
                pkt = simple_tcp_packet(
                        vlan_tags=[{'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp}])
        else:
            pkt = simple_tcp_packet()

    if exp_pkt is None:
        if exp_vid >= 0 and exp_vid != ofp.OFPVID_NONE:
            if add_tag_exp:
                if dl_vlan >= 0 and dl_vlan != ofp.OFPVID_NONE:
                    if dl_vlan_int >= 0 and dl_vlan_int != ofp.OFPVID_NONE:
                        exp_pkt = simple_tcp_packet(
                                    vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                               {'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp},
                                               {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
                    else:
                        exp_pkt = simple_tcp_packet(
                                    vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                               {'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp}])
                else:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp}])
            else:
                if dl_vlan_int >= 0:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                           {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])

                else:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp}])
        else:
            #subtract action
            if dl_vlan_int >= 0:
                exp_pkt = simple_tcp_packet(
                            vlan_tags=[{'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
            else:
                exp_pkt = simple_tcp_packet()

    match = parse.packet_to_flow_match(pkt)
    parent.assertTrue(match is not None, "Flow match from pkt failed")

    match.dl_vlan = vid_match
    match.dl_vlan_pcp = pcp_match
    match.wildcards = wildcards

    request = flow_msg_create(parent, pkt, ing_port=ing_port,
                              wildcards=wildcards,
                              match=match,
                              egr_port=egr_port,
                              action_list=action_list)

    flow_msg_install(parent, request)

    logging.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    logging.debug("Sent:" + str(pkt).encode('hex'))
    parent.dataplane.send(ing_port, str(pkt))

    if match_exp:
        receive_pkt_verify(parent, egr_port, exp_pkt)
        if check_expire:
            #@todo Not all HW supports both pkt and byte counters
            flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))
    else:
        if exp_msg is ofp.OFPT_FLOW_REMOVED:
            if check_expire:
                flow_removed_verify(parent, request, pkt_count=0, byte_count=0)
        elif exp_msg is ofp.OFPT_ERROR:
            error_verify(parent, exp_msg_type, exp_msg_code)
        else:
            parent.assertTrue(0, "Rcv: Unexpected Message: " + str(exp_msg))

        (_, rcv_pkt, _) = parent.dataplane.poll(timeout=1)
        parent.assertFalse(rcv_pkt is not None, "Packet on dataplane")

def flow_match_test_vlan(parent, port_map, wildcards=0,
                         dl_vlan=ofp.OFPVID_NONE, dl_vlan_pcp=0, dl_vlan_type=ETHERTYPE_VLAN,
                         dl_vlan_int=-1, dl_vlan_pcp_int=0,
                         vid_match=ofp.OFPVID_NONE, pcp_match=0,
                         exp_vid=-1, exp_pcp=0,
                         exp_vlan_type=ETHERTYPE_VLAN,
                         match_exp=True,
                         add_tag_exp=False,
                         exp_msg=ofp.OFPT_FLOW_REMOVED,
                         exp_msg_type=0, exp_msg_code=0,
                         pkt=None, exp_pkt=None,
                         action_list=None,
                         check_expire=False,
                         max_test=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param wildcards For flow match entry
    @param dl_vlan If not -1, and pkt is not None, create a pkt w/ VLAN tag
    @param dl_vlan_pcp VLAN PCP associated with dl_vlan
    @param dl_vlan_type VLAN ether type associated with dl_vlan
    @param dl_vlan_int If not -1, create pkt w/ Inner Vlan tag
    @param dl_vlan_pcp_int VLAN PCP associated with dl_vlan_2nd
    @param vid_match Matching value for VLAN VID field
    @param pcp_match Matching value for VLAN PCP field
    @param exp_vid Expected VLAN VID value. If -1, no VLAN expected
    @param exp_vlan_type Expected VLAN ether type
    @param exp_pcp Expected VLAN PCP value
    @param match_exp Set whether packet is expected to receive
    @param add_tag_exp If True, expected_packet has an additional vlan tag,
    If not, expected_packet's vlan tag is replaced as specified
    @param exp_msg Expected message
    @param exp_msg_type Expected message type associated with the message
    @param exp_msg_code Expected message code associated with the msg_type
    @param pkt If not None, use this packet for ingress
    @param exp_pkt If not None, use this as the expected output pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair_vlan(parent, ingress_port, egress_port,
                                           wildcards=wildcards,
                                           dl_vlan=dl_vlan,
                                           dl_vlan_pcp=dl_vlan_pcp,
                                           dl_vlan_type=dl_vlan_type,
                                           dl_vlan_int=dl_vlan_int,
                                           dl_vlan_pcp_int=dl_vlan_pcp_int,
                                           vid_match=vid_match,
                                           pcp_match=pcp_match,
                                           exp_vid=exp_vid,
                                           exp_pcp=exp_pcp,
                                           exp_vlan_type=exp_vlan_type,
                                           exp_msg=exp_msg,
                                           exp_msg_type=exp_msg_type,
                                           exp_msg_code=exp_msg_code,
                                           match_exp=match_exp,
                                           add_tag_exp=add_tag_exp,
                                           pkt=pkt, exp_pkt=exp_pkt,
                                           action_list=action_list,
                                           check_expire=check_expire)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                logging.info("Ran " + str(test_count) + " tests; exiting")
                return

def test_param_get(config, key, default=None):
    """
    Return value passed via test-params if present

    @param config The configuration structure for OFTest
    @param key The lookup key
    @param default Default value to use if not found

    If the pair 'key=val' appeared in the string passed to --test-params
    on the command line, return val (as interpreted by exec).  Otherwise
    return default value.
    """
    try:
        exec config["test_params"]
    except:
        return default

    s = "val = " + str(key)
    try:
        val = None
        exec s
        return val
    except:
        return default

def action_generate(parent, field_to_mod, mod_field_vals):
    """
    Create an action to modify the field indicated in field_to_mod

    @param parent Must implement, assertTrue
    @param field_to_mod The field to modify as a string name
    @param mod_field_vals Hash of values to use for modified values
    """

    act = None

    if field_to_mod in ['pktlen']:
        return None

    if field_to_mod == 'dl_dst':
        act = action.set_dl_dst()
        act.dl_addr = parse.parse_mac(mod_field_vals['dl_dst'])
    elif field_to_mod == 'dl_src':
        act = action.set_dl_src()
        act.dl_addr = parse.parse_mac(mod_field_vals['dl_src'])
    elif field_to_mod == 'vlan_tags':
        if len(mod_field_vals['vlan_tags']):
            act = action.pop_vlan()
        else:
            pass
#    elif field_to_mod == 'dl_vlan_enable':
#        if not mod_field_vals['dl_vlan_enable']: # Strip VLAN tag
#            act = action.pop_vlan()
#        # Add VLAN tag is handled by dl_vlan field
#        # Will return None in this case
#    elif field_to_mod == 'dl_vlan':
#        act = action.set_vlan_vid()
#        act.vlan_vid = mod_field_vals['dl_vlan']
#    elif field_to_mod == 'dl_vlan_pcp':
#        act = action.set_vlan_pcp()
#        act.vlan_pcp = mod_field_vals['dl_vlan_pcp']
    elif field_to_mod == 'ip_src':
        act = action.set_nw_src()
        act.nw_addr = parse.parse_ip(mod_field_vals['ip_src'])
    elif field_to_mod == 'ip_dst':
        act = action.set_nw_dst()
        act.nw_addr = parse.parse_ip(mod_field_vals['ip_dst'])
    elif field_to_mod == 'ip_tos':
        act = action.set_nw_tos()
        act.nw_tos = mod_field_vals['ip_tos']
    elif field_to_mod == 'tcp_sport':
        act = action.set_tp_src()
        act.tp_port = mod_field_vals['tcp_sport']
    elif field_to_mod == 'tcp_dport':
        act = action.set_tp_dst()
        act.tp_port = mod_field_vals['tcp_dport']
    else:
        parent.assertTrue(0, "Unknown field to modify: " + str(field_to_mod))

    return act

def pkt_action_setup(parent, start_field_vals={}, mod_field_vals={}, 
                     mod_fields={}, check_test_params=False):
    """
    Set up the ingress and expected packet and action list for a test

    @param parent Must implement, assertTrue, config hash and logger
    @param start_field_values Field values to use for ingress packet (optional)
    @param mod_field_values Field values to use for modified packet (optional)
    @param mod_fields The list of fields to be modified by the switch in the test.
    @params check_test_params If True, will check the parameters vid, add_vlan
    and strip_vlan from the command line.

    Returns a triple:  pkt-to-send, expected-pkt, action-list
    """

    new_actions = []


    base_pkt_params = {}
    base_pkt_params['dl_dst'] = '00:DE:F0:12:34:56'
    base_pkt_params['dl_src'] = '00:23:45:67:89:AB'
#    base_pkt_params['dl_vlan_enable'] = False
#    base_pkt_params['dl_vlan'] = 2
#    base_pkt_params['dl_vlan_pcp'] = 0
    base_pkt_params['ip_src'] = '192.168.0.1'
    base_pkt_params['ip_dst'] = '192.168.0.2'
    base_pkt_params['ip_tos'] = 0
    base_pkt_params['tcp_sport'] = 1234
    base_pkt_params['tcp_dport'] = 80
    for keyname in start_field_vals.keys():
        base_pkt_params[keyname] = start_field_vals[keyname]

    mod_pkt_params = {}
    mod_pkt_params['dl_dst'] = '00:21:0F:ED:CB:A9'
    mod_pkt_params['dl_src'] = '00:ED:CB:A9:87:65'
#    mod_pkt_params['dl_vlan_enable'] = False
#    mod_pkt_params['dl_vlan'] = 3
#    mod_pkt_params['dl_vlan_pcp'] = 7
    mod_pkt_params['ip_src'] = '10.20.30.40'
    mod_pkt_params['ip_dst'] = '50.60.70.80'
    mod_pkt_params['ip_tos'] = 0xf0
    mod_pkt_params['tcp_sport'] = 4321
    mod_pkt_params['tcp_dport'] = 8765
    for keyname in mod_field_vals.keys():
        mod_pkt_params[keyname] = mod_field_vals[keyname]

    # Check for test param modifications
    strip = False
    if check_test_params:
        add_vlan = test_param_get(parent.config, 'add_vlan')
        strip_vlan = test_param_get(parent.config, 'strip_vlan')
        vid = test_param_get(parent.config, 'vid')

        if add_vlan and strip_vlan:
            parent.assertTrue(0, "Add and strip VLAN both specified")

        if vid:
            base_pkt_params['dl_vlan_enable'] = True
            base_pkt_params['dl_vlan'] = vid
            if 'dl_vlan' in mod_fields:
                mod_pkt_params['dl_vlan'] = vid + 1

        if add_vlan:
            base_pkt_params['dl_vlan_enable'] = False
            mod_pkt_params['dl_vlan_enable'] = True
            mod_pkt_params['pktlen'] = base_pkt_params['pktlen'] + 4
            mod_fields.append('pktlen')
            mod_fields.append('dl_vlan_enable')
            if 'dl_vlan' not in mod_fields:
                mod_fields.append('dl_vlan')
        elif strip_vlan:
            base_pkt_params['dl_vlan_enable'] = True
            mod_pkt_params['dl_vlan_enable'] = False
            mod_pkt_params['pktlen'] = base_pkt_params['pktlen'] - 4
            mod_fields.append('dl_vlan_enable')
            mod_fields.append('pktlen')

    # Build the ingress packet
    ingress_pkt = simple_tcp_packet(**base_pkt_params)

    # Build the expected packet, modifying the indicated fields
    for item in mod_fields:
        base_pkt_params[item] = mod_pkt_params[item]
        act = action_generate(parent, item, mod_pkt_params)
        if act:
            new_actions.append(act)

    expected_pkt = simple_tcp_packet(**base_pkt_params)

    return (ingress_pkt, expected_pkt, new_actions)
        
def wildcard_all_set(match):
    match.wildcards = ofp.OFPFW_ALL
    match.nw_dst_mask = 0xffffffff
    match.nw_src_mask = 0xffffffff
    match.dl_dst_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    match.dl_src_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    match.metadata_mask = 0xffffffffffffffff

def skip_message_emit(parent, s):
    """
    Print out a 'skipped' message to stderr

    @param s The string to print out to the log file
    @param parent Must implement config and logger objects
    """
    global skipped_test_count

    skipped_test_count += 1
    logging.info("Skipping: " + s)
    if parent.config["debug"] < logging.WARNING:
        sys.stderr.write("(skipped) ")
    else:
        sys.stderr.write("(S)")

def do_echo_request_reply_test(test,controller):
        request = message.echo_request()
        response, _ = controller.transact(request)
        test.assertEqual(response.header.type, ofp.OFPT_ECHO_REPLY,
                         'response is not echo_reply')
        test.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')
        test.assertEqual(len(response.data), 0, 'response data non-empty')

def match_all_generate():
    match = ofp.ofp_match()
    return match

def simple_tcp_packet_w_mpls(
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      mpls_type=0x8847,
                      mpls_label=-1,
                      mpls_tc=0,
                      mpls_ttl=64,
                      mpls_label_int=-1,
                      mpls_tc_int=0,
                      mpls_ttl_int=32,
                      mpls_label_ext=-1,
                      mpls_tc_ext=0,
                      mpls_ttl_ext=128,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_tos=0,
                      ip_ttl=192,
                      tcp_sport=1234,
                      tcp_dport=80
                      ):
    """
    Return a simple dataplane TCP packet w/wo MPLS tags

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param mpls_type MPLS type as ether type
    @param mpls_label MPLS LABEL if not -1
    @param mpls_tc MPLS TC
    @param mpls_ttl MPLS TTL
    @param mpls_label_int Inner MPLS LABEL if not -1. The shim will be added
    inside of mpls_label shim.
    @param mpls_tc_int Inner MPLS TC
    @param mpls_ttl_int Inner MPLS TTL
    @param mpls_label_ext External MPLS LABEL if not -1. The shim will be
    added outside of mpls_label shim
    @param mpls_tc_ext External MPLS TC
    @param mpls_ttl_ext External MPLS TTL
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    Generates a simple MPLS/IP/TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """
    
    mpls_tags = []
    
    if mpls_label_ext >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label_ext, 'tc': mpls_tc_ext, 'ttl': mpls_ttl_ext})
        
    if mpls_label >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label, 'tc': mpls_tc, 'ttl': mpls_ttl})
        
    if mpls_label_int >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label_int, 'tc': mpls_tc_int, 'ttl': mpls_ttl_int})
    
    pkt = simple_tcp_packet(dl_dst=dl_dst,
                            dl_src=dl_src,
                            mpls_tags=mpls_tags,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_tos=ip_tos,  
                            ip_ttl=ip_ttl,
                            tcp_sport=tcp_sport,
                            tcp_dport=tcp_dport)
    return pkt
    
def flow_match_test_port_pair_mpls(parent, ing_port, egr_port, wildcards=0,
                                   mpls_type=0x8847,
                                   mpls_label=-1, mpls_tc=0,mpls_ttl=64,
                                   mpls_label_int=-1, mpls_tc_int=0,
                                   mpls_ttl_int=32,
                                   ip_ttl=192,
                                   exp_mpls_type=0x8847,
                                   exp_mpls_label=-1, exp_mpls_tc=0,
                                   exp_mpls_ttl=64,
                                   exp_mpls_ttl_int=32,
                                   exp_ip_ttl=192,
                                   label_match=0, tc_match=0,
                                   dl_type_match=ETHERTYPE_MPLS,
                                   match_exp=True,
                                   add_tag_exp=False,
                                   exp_msg=ofp.OFPT_FLOW_REMOVED,
                                   exp_msg_type=0, exp_msg_code=0,
                                   pkt=None,
                                   exp_pkt=None, action_list=None,
                                   check_expire=False):
    """
    Flow match test on single packet w/ MPLS tags

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test for parameter descriptions
    """
    logging.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    logging.debug("  WC: " + hex(wildcards) + " MPLS: " +
                    str(mpls_label) + " expire: " + str(check_expire))

    if pkt is None:

        pkt = simple_tcp_packet_w_mpls(mpls_type=mpls_type,
                                       mpls_label=mpls_label,
                                       mpls_tc=mpls_tc,
                                       mpls_ttl=mpls_ttl,
                                       mpls_label_int=mpls_label_int,
                                       mpls_tc_int=mpls_tc_int,
                                       mpls_ttl_int=mpls_ttl_int,
                                       ip_ttl=ip_ttl)

    if exp_pkt is None:
        if add_tag_exp:
            exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=exp_mpls_type,
                                           mpls_label_ext=exp_mpls_label,
                                           mpls_tc_ext=exp_mpls_tc,
                                           mpls_ttl_ext=exp_mpls_ttl,
                                           mpls_label=mpls_label,
                                           mpls_tc=mpls_tc,
                                           mpls_ttl=mpls_ttl,
                                           mpls_label_int=mpls_label_int,
                                           mpls_tc_int=mpls_tc_int,
                                           mpls_ttl_int=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
        else:
            if (exp_mpls_label < 0) and (mpls_label_int >= 0):
                exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=mpls_type,
                                           mpls_label=mpls_label_int,
                                           mpls_tc=mpls_tc_int,
                                           mpls_ttl=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
            else:
                exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=exp_mpls_type,
                                           mpls_label=exp_mpls_label,
                                           mpls_tc=exp_mpls_tc,
                                           mpls_ttl=exp_mpls_ttl,
                                           mpls_label_int=mpls_label_int,
                                           mpls_tc_int=mpls_tc_int,
                                           mpls_ttl_int=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
    wildcards = (ofp.OFPFW_ALL & ~(ofp.OFPFW_DL_TYPE | ofp.OFPFW_MPLS_LABEL | ofp.OFPFW_MPLS_TC)) | wildcards

    match = parse.packet_to_flow_match(pkt)
    parent.assertTrue(match is not None, "Flow match from pkt failed")

    match.mpls_label = label_match
    match.mpls_tc = tc_match
    match.wildcards = wildcards

    match.dl_type = dl_type_match
    match.nw_tos = 0
    match.nw_proto = 0
    match.nw_src = 0
    match.nw_src_mask = 0xFFFFFFFF
    match.nw_dst = 0
    match.nw_dst_mask = 0xFFFFFFFF
    match.tp_src = 0
    match.tp_dst = 0

    request = flow_msg_create(parent, pkt, ing_port=ing_port,
                              wildcards=wildcards,
                              match=match,
                              egr_port=egr_port,
                              action_list=action_list)

    flow_msg_install(parent, request)

    logging.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    #logging.debug(str(pkt).encode("hex"))
    parent.dataplane.send(ing_port, str(pkt))

    if match_exp:
        receive_pkt_verify(parent, egr_port, exp_pkt)
        if check_expire:
            #@todo Not all HW supports both pkt and byte counters
            flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))
    else:
        if exp_msg == ofp.OFPT_FLOW_REMOVED:
            if check_expire:
                flow_removed_verify(parent, request, pkt_count=0, byte_count=0)
        elif exp_msg == ofp.OFPT_ERROR:
            error_verify(parent, exp_msg_type, exp_msg_code)
        else:
            parent.assertTrue(0, "Rcv: Unexpected Message: " + str(exp_msg))
        (_, rcv_pkt, _) = parent.dataplane.poll(timeout=1)
        parent.assertFalse(rcv_pkt is not None, "Packet on dataplane")

def flow_match_test_mpls(parent, port_map, wildcards=0,
                         mpls_type=0x8847,
                         mpls_label=-1, mpls_tc=0, mpls_ttl=64,
                         mpls_label_int=-1, mpls_tc_int=0, mpls_ttl_int=32,
                         ip_ttl = 192,
                         label_match=0, tc_match=0,
                         dl_type_match=ETHERTYPE_MPLS,
                         exp_mpls_type=0x8847,
                         exp_mpls_label=-1, exp_mpls_tc=0, exp_mpls_ttl=64,
                         exp_mpls_ttl_int=32,
                         exp_ip_ttl=192,
                         match_exp=True,
                         add_tag_exp=False,
                         exp_msg=ofp.OFPT_FLOW_REMOVED,
                         exp_msg_type=0, exp_msg_code=0,
                         pkt=None,
                         exp_pkt=None, action_list=None, check_expire=False,
                         max_test=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param wildcards For flow match entry
    @param mpls_type MPLS type
    @param mpls_label If not -1 create a pkt w/ MPLS tag
    @param mpls_tc MPLS TC associated with MPLS label
    @param mpls_ttl MPLS TTL associated with MPLS label
    @param mpls_label_int If not -1 create a pkt w/ Inner MPLS tag
    @param mpls_tc_int MPLS TC associated with Inner MPLS label
    @param mpls_ttl_int MPLS TTL associated with Inner MPLS label
    @param ip_ttl IP TTL
    @param label_match Matching value for MPLS LABEL field
    @param tc_match Matching value for MPLS TC field
    @param exp_mpls_label Expected MPLS LABEL value. If -1, no MPLS expected
    @param exp_mpls_tc Expected MPLS TC value
    @param exp_mpls_ttl Expected MPLS TTL value
    @param exp_mpls_ttl_int Expected Inner MPLS TTL value
    @param ip_ttl Expected IP TTL
    @param match_exp Set whether packet is expected to receive
    @param add_tag_exp If True, expected_packet has an additional MPLS shim,
    If not expected_packet's MPLS shim is replaced as specified
    @param exp_msg Expected message
    @param exp_msg_type Expected message type associated with the message
    @param exp_msg_code Expected message code associated with the msg_type
    @param pkt If not None, use this packet for ingress
    @param exp_pkt If not None, use this as the expected output pkt; els use pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair_mpls(parent, ingress_port, egress_port,
                                      wildcards=wildcards,
                                      mpls_type=mpls_type,
                                      mpls_label=mpls_label,
                                      mpls_tc=mpls_tc,
                                      mpls_ttl=mpls_ttl,
                                      mpls_label_int=mpls_label_int,
                                      mpls_tc_int=mpls_tc_int,
                                      mpls_ttl_int=mpls_ttl_int,
                                      ip_ttl=ip_ttl,
                                      label_match=label_match,
                                      tc_match=tc_match,
                                      dl_type_match=dl_type_match,
                                      exp_mpls_type=exp_mpls_type,
                                      exp_mpls_label=exp_mpls_label,
                                      exp_mpls_tc=exp_mpls_tc,
                                      exp_mpls_ttl=exp_mpls_ttl,
                                      exp_mpls_ttl_int=exp_mpls_ttl_int,
                                      exp_ip_ttl=exp_ip_ttl,
                                      match_exp=match_exp,
                                      exp_msg=exp_msg,
                                      exp_msg_type=exp_msg_type,
                                      exp_msg_code=exp_msg_code,
                                      add_tag_exp=add_tag_exp,
                                      pkt=pkt, exp_pkt=exp_pkt,
                                      action_list=action_list,
                                      check_expire=check_expire)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                logging.info("Ran " + str(test_count) + " tests; exiting")
                return

def flow_stats_get(parent, match_fields = None):
    """ Get the flow_stats from the switch
    Test the response to make sure it's really a flow_stats object
    """
    request = message.flow_stats_request()
    request.out_port = ofp.OFPP_ANY
    request.out_group = ofp.OFPG_ANY
    request.table_id = 0xff
    if match_fields != None:
        request.match_fields = match_fields
    response, _ = parent.controller.transact(request, timeout=2)
    parent.assertTrue(response is not None, "Did not get response")
    parent.assertTrue(isinstance(response,message.flow_stats_reply),
                      "Expected a flow_stats_reply, but didn't get it")
    return response
