from scapy.all import *

'''
This module contains some scapy definitions of Link Layer Bluetooth Low Energy packets.
'''

class ControlPDU(Packet):
	name = "Control PDU"
	fields_desc = [
		XByteField("opcode", 0)
	]

class LL_ENC_REQ(Packet):
	name = "LL_ENC_REQ"
	fields_desc = [
		XLELongField("rand",None), 
		XLEShortField("ediv",None),
		XLELongField("skd",None),
		XLEIntField("iv",None)
	]

class LL_ENC_RSP(Packet):
	name = "LL_ENC_RSP"
	fields_desc = [
		XLELongField("skd",None),
		XLEIntField("iv",None)
	]
split_layers(BTLE_DATA, BTLE_CTRL)
bind_layers(BTLE_DATA, BTLE_CTRL, LLID=3)
bind_layers(BTLE_CTRL,LL_ENC_REQ,opcode=0x03)
bind_layers(BTLE_CTRL,LL_ENC_RSP,opcode=0x04)
