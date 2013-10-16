'''
Created on Aug 26, 2013

@author: hcl-tellabs
'''

import logging
import time
import unittest
import ofp
from oftest import config
import oftest.testutils as testutils
import oftest.base_tests as base_tests
import ofp.message as message
import ofp.match as match
from ofp.match_list import match_list
import oftest.sshconnect as sshconnect

"""
def setUpModule():
    logging.info("Attempting to start OMA CLI Session")
    cli = sshconnect.sshconnect(
          host=config["cli_host"],
          port=config["cli_port"],
          user=config["cli_user"],
          passwd=config["cli_passwd"])
    cli.start()
    try:
       cli.connect()
    except:
       logging.debug("Telnet to OMA CLI failed. Please verify the IP,Port,User or Password")
       raise Exception("Telnet to OMA CLI failed. Please verify the IP,Port,User or Password")
    if cli.default_config():
       testutils.printConLog("Configuration Success")
    else:
       testutils.printConLog("Configuration Failed")
       raise Exception("Configuration Failed")
    cli.close()

def tearDownModule():
    logging.info("Attempting to start OMA CLI Session")
    cli = sshconnect.sshconnect(
          host=config["cli_host"],
          port=config["cli_port"],
          user=config["cli_user"],
          passwd=config["cli_passwd"])
    cli.start()
    try:
       cli.connect()
    except:
       logging.debug("Telnet to OMA CLI failed. Please verify the IP,Port,User or Password")
       raise Exception("Telnet to OMA CLI failed. Please verify the IP,Port,User or Password")
    cli.default_unconfig()
    cli.close()

"""
class T7100_SDN_OFP_15(base_tests.SimpleSSHCtrl):
    """ To Test whether OMA is capable of processing FLOW MOD ADD message
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()

        testutils.printConLog("  Give Inputs for FLOW_MOD ADD message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD ADD Message")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        request.flags = ofp.OFPFF_SEND_FLOW_REM
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD ADD Message")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type: " + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received Message " + reply.header.type)
        else:
            testutils.printConLog("Flow Mod Add request sent successfully")

        self.cli.close()


class T7100_SDN_OFP_FLOW_MOD_DEL(base_tests.SimpleSSHCtrl):
    """ To Test whether OMA is capable of processing FLOW MOD DELETE Message
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()

        testutils.printConLog("  Give Inputs for FLOW_MOD DELETE Message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD DELETE Message")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
        request.command = ofp.OFPFC_DELETE_STRICT
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD DELETE Message")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type:" + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received " + reply.header.type)
        else:
            testutils.printConLog("FLOW_MOD DELETE Message sent successfully")

        self.cli.close()


class T7100_SDN_OFP_CRS_CREATE(base_tests.SimpleSSHCtrl):
    """ Send a CRS Create with two FLOW_MOD ADD Messages.
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()
        
        testutils.printConLog("  Give Inputs for FLOW_MOD ADD message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD ADD Message 1")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        request = message.flow_mod()
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        request.flags = ofp.OFPFF_SEND_FLOW_REM
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD ADD Message 1")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type:" + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received " + reply.header.type)
        else:
            testutils.printConLog(s="FLOW_MOD ADD Message 1 sent successfully")

        print 
        testutils.printConLog("Building FLOW_MOD ADD Message 2")
        match_fields = match_list()
        match_fields.add(inpDict['m_outport'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_inport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        request.flags = ofp.OFPFF_SEND_FLOW_REM
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD ADD Message 2")
        reply = self.controller.message_send(request)
        if reply != 0:
           testutils.printConLog("FLOW_MOD ADD Message 2 Failed")
        else:
           testutils.printConLog("FLOW_MOD ADD Message 2 sent Successfully") 

        testutils.printConLog("Sending Barrier request")
        b1 = message.barrier_request()
        reply = self.controller.message_send(b1)
        self.cli.close()

"""
        valuesDict = {'from_och':'OCH-L-1-1-1-1','to_och':'OCH-P-2-3-3'}
        testutils.printConLog("Checking the CRS " + str(valuesDict) + " in 7100 Simulator")
        time.sleep(60)

        self.tl1()
        self.assertEqual(self.tl1.sendCMD("RTRV-CRS-OCH", valuesDict),1,'CRS Create Failed')
        testutils.printConLog("CRS Create Success")
"""


class T7100_SDN_OFP_CRS_DELETE(base_tests.SimpleSSHCtrl):
    """ Send a CRS Delete with two FLOW_MOD DELETE Messages.
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()

        testutils.printConLog("  Give Inputs for FLOW_MOD DELETE Message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD DELETE Message 1")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        request = message.flow_mod()
#        request.command = ofp.OFPFC_DELETE_STRICT
        request.command = ofp.OFPFC_DELETE
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD DELETE Message 1")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type:" + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received " + reply.header.type)
        else:
            testutils.printConLog("FLOW_MOD DELETE Message 1 Success")

        print 
        testutils.printConLog("Building FLOW_MOD DELETE Message 2")
        match_fields = match_list()
        match_fields.add(inpDict['m_outport'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_inport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
#        request.command = ofp.OFPFC_DELETE_STRICT
        request.command = ofp.OFPFC_DELETE
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD DELETE Message 2")
        reply = self.controller.message_send(request)
        if reply != 0:
           testutils.printConLog("FLOW_MOD DELETE Message 2 Failed")
        else:
           testutils.printConLog("FLOW_MOD DELETE Message 2 Success")

        testutils.printConLog("Sending Barrier request")
        b1 = message.barrier_request()
        reply = self.controller.message_send(b1)
        self.cli.close()
"""
        valuesDict = {'from_och':'OCH-L-1-1-1-1','to_och':'OCH-P-2-3-3'}
        testutils.printConLog("Checking CRS " + str(valuesDict) + " in 7100 Simulator")
        time.sleep(60)

        self.tl1()
        self.assertEqual(self.tl1.sendCMD("RTRV-CRS-OCH", valuesDict),0,'CRS Delete Failed')
        testutils.printConLog("CRS Delete Success")
"""


class T7100_SDN_OFP_ODU_CREATE(base_tests.SimpleSSHCtrl):
    """ Send a ODU CRS Create with two FLOW_MOD ADD Messages.
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()
        
        testutils.printConLog("  Give Inputs for FLOW_MOD ADD message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD ADD Message 1")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        request.flags = ofp.OFPFF_SEND_FLOW_REM
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD ADD Message 1")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type:" + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received " + reply.header.type)
        else:
            testutils.printConLog(s="FLOW_MOD ADD Message 1 sent successfully")
        self.cli.close()

        print 
        testutils.printConLog("Building FLOW_MOD ADD Message 2")
        match_fields = match_list()
        match_fields.add(inpDict['m_outport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label_msg2'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_inport'])
        inst.actions.add(inpDict['a_label_msg2'])
        request = message.flow_mod()
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        request.flags = ofp.OFPFF_SEND_FLOW_REM
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD ADD Message 2")
        reply = self.controller.message_send(request)
        if reply != 0:
           testutils.printConLog("FLOW_MOD ADD Message 2 Failed")
        else:
           testutils.printConLog("FLOW_MOD ADD Message 2 sent Successfully") 

        testutils.printConLog("Sending Barrier request")
        b1 = message.barrier_request()
        reply = self.controller.message_send(b1)
        self.cli.close()


class T7100_SDN_OFP_ODU_DELETE(base_tests.SimpleSSHCtrl):
    """ Send a ODU Delete with two FLOW_MOD DELETE Messages.
    """
    def runTest(self):
        testutils.printConLog(self.__class__.__doc__)
        self.ctrl()

        testutils.printConLog("  Give Inputs for FLOW_MOD DELETE Message")
        inpDict = testutils.getflowInputs(self)

        testutils.printConLog("Building FLOW_MOD DELETE Message 1")
        match_fields = match_list()
        match_fields.add(inpDict['m_inport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_outport'])
        inst.actions.add(inpDict['a_label'])
        request = message.flow_mod()
#        request.command = ofp.OFPFC_DELETE_STRICT
        request.command = ofp.OFPFC_DELETE
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD DELETE Message 1")
        reply, _ = self.controller.transact(request, timeout=2)
        if reply is not None:
           if reply.header.type == ofp.OFPT_ERROR:
              testutils.printConLog(s="Received Error message with Type:" + reply.type + " Code: " + reply.code)
              logging.debug(reply.show())
           else:
              testutils.printConLog(s="Received " + reply.header.type)
        else:
            testutils.printConLog("FLOW_MOD DELETE Message 1 Success")

        print 
        testutils.printConLog("Building FLOW_MOD DELETE Message 2")
        match_fields = match_list()
        match_fields.add(inpDict['m_outport'])
        match_fields.add(inpDict['m_swcapenctype'])
        match_fields.add(inpDict['m_sigtype'])
        match_fields.add(inpDict['m_label_msg2'])
        inst = ofp.instruction.instruction_write_actions()
        inst.actions.add(inpDict['a_inport'])
        inst.actions.add(inpDict['a_label_msg2'])
        request = message.flow_mod()
#        request.command = ofp.OFPFC_DELETE_STRICT
        request.command = ofp.OFPFC_DELETE
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.match_fields = match_fields
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        logging.debug(request.show())

        testutils.printConLog("Sending FLOW_MOD DELETE Message 2")
        reply = self.controller.message_send(request)
        if reply != 0:
           testutils.printConLog("FLOW_MOD DELETE Message 2 Failed")
        else:
           testutils.printConLog("FLOW_MOD DELETE Message 2 Success")

        testutils.printConLog("Sending Barrier request")
        b1 = message.barrier_request()
        reply = self.controller.message_send(b1)
        self.cli.close()


if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=flow_mod"
