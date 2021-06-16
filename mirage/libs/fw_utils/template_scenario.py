#!/usr/bin/env python3

from mirage.core import scenario
from mirage.libs.fw_utils import firewall_rules
from mirage.libs import io,ble,utils
import tempfile
import os


class {0}(scenario.Scenario):
	def __init__(self, *args, **kwargs):
		scenario.Scenario.__init__(self,*args,**kwargs)
		self.rule_dictionnary=dict()
		self.removedUUIDs=set()
		self.removedHandles=[]
		self.maxHandle=None
		self.mitmRunning=False
		_,self.discovered=tempfile.mkstemp()
		os.close(_)
		{1}

	def runDiscover(self):
		newConnection=False
		if (not self.module.a2sEmitter) or not self.module.a2sEmitter.isConnected():
			newConnection=True
			connect_module = utils.loadModule("ble_connect")
			connect_module.args["INTERFACE"] = self.module.args["INTERFACE1"]
			connect_module.args["TARGET"] = self.module.args["TARGET"]
			assert connect_module.execute()["success"]

		discover_module = utils.loadModule("ble_discover")
		discover_module.args["INTERFACE"] = self.module.args["INTERFACE1"]
		discover_module.args["GATT_FILE"] = self.discovered

		try:

			assert discover_module.execute()["success"]

			if newConnection:
				self.module.a2sEmitter.sendp(ble.BLEDisconnect())
				while self.module.a2sEmitter.isConnected():
					pass

			with open(self.discovered) as f:
				content=f.read().strip().split("\n")

			self.removedHandles=[]

			handles=dict()

			c=0
			n=len(content)
			while c<n and content[c]=="":
				c+=1

			while c<n:
				line = content[c]
				handle = utils.integerArg(line.strip()[1:-1])
				c+=1

				t = content[c][7:]
				c+=1

				line = content[c]
				uuid = utils.integerArg(line[7:])

				if t=="service":
					c+=1
					line = content[c]
					endHandle = utils.integerArg(line[12:])
					for handle2 in range(handle, endHandle+1):
						if handle2 not in handles:
							handles[handle2]=set()
						handles[handle2].add(uuid)
				elif t=="characteristic":
					c+=3
					line = content[c]
					valueHandle = utils.integerArg(line[14:])
					if handle not in handles:
						handles[handle]=set()
					handles[handle].add(uuid)
					if valueHandle not in handles:
						handles[valueHandle]=set()
					handles[valueHandle].add(uuid)
				elif t=="descriptor":
					if handle not in handles:
						handles[handle]=set()
					handles[handle].add(uuid)
				else:
					raise ValueError("Unknown type found in discovery result :",t)

				while c<n and content[c]!="":
					c+=1 # skip other fields
				while c<n and content[c]=="":
					c+=1 # skip empty lines

			n=len(handles)
			handles_list=list(handles.keys())
			for i,handle in enumerate(handles_list):
				if handles[handle].intersection(self.removedUUIDs):
					self.removedHandles.append((handle,handle))
			self.maxHandle=max(handles_list)
		finally:
			if os.path.isfile(self.discovered):
				os.remove(self.discovered)

	def checkSlaveHandle(self, handle):
		for start,stop in self.removedHandles:
			if handle>=start and handle<=stop:
				return False
		return True

	def _translateSingleHandleSlave(self,handle):
		toRemove = 0
		for start,end in self.removedHandles:
			if start<=handle:
				toRemove+=end-start+1 # end is included
			else:
				break
		return handle-toRemove


	def translateHandlesFromSlave(self, packet): 
		io.info("Translating from Slave : "+packet.__repr__())
		if type(packet)==ble.BLEReadByGroupTypeResponse:
			new_attrs=[]
			for attr in packet.attributes:
				if int.from_bytes(attr["value"],"little") not in self.removedUUIDs and attr['attributeHandle'] not in [h[0] for h in self.removedHandles]:
					new_attr=dict()
					new_attr['attributeHandle']=self._translateSingleHandleSlave(attr['attributeHandle'])
					new_attr['endGroupHandle']=self._translateSingleHandleSlave(attr['endGroupHandle']) if attr['endGroupHandle']!=0xFFFF else 0xFFFF
					new_attr['value']=attr['value']
					new_attrs.append(new_attr)
			if new_attrs:
				io.info(packet.__repr__()+" translated to "+ble.BLEReadByGroupTypeResponse(attributes=new_attrs).__repr__())
				packet.attributes=new_attrs
				packet.build()
				return True
			else:
				io.info(packet.__repr__()+" dropped (handle removed)")
				return False
		elif type(packet)==ble.BLEReadByTypeResponse:
			new_attrs=[]
			for attr in packet.attributes:
				uuid=int.from_bytes(attr['value'][3:], "little")
				n_uuid=len(attr['value'][3:])
				valueHandle=int.from_bytes(attr['value'][1:3], "little")
				if uuid not in self.removedUUIDs and attr['attributeHandle'] not in [h[0] for h in self.removedHandles] and valueHandle not in [h[0] for h in self.removedHandles]:
					new_attr=dict()
					new_attr['attributeHandle']=self._translateSingleHandleSlave(attr['attributeHandle'])
					newValueHandle=self._translateSingleHandleSlave(valueHandle)
					new_attr['value']=attr['value'][:1]+newValueHandle.to_bytes(2,"little")+attr['value'][3:]
					new_attrs.append(new_attr)
			if new_attrs:
				io.info(packet.__repr__()+" translated to "+ble.BLEReadByTypeResponse(attributes=new_attrs).__repr__())
				packet.attributes=new_attrs
				packet.build()
				return True
			else:
				io.info(packet.__repr__()+" dropped (handle removed)")
				return False
		elif type(packet)==ble.BLEFindInformationResponse:
			new_attrs=[]
			for attr in packet.attributes:
				if attr['attributeHandle'] not in [h[0] for h in self.removedHandles]:
					new_attr=dict()
					new_attr['attributeHandle']=self._translateSingleHandleSlave(attr['attributeHandle'])
					new_attr['type']=attr['type']
					new_attrs.append(new_attr)
			if new_attrs:
				io.info(packet.__repr__()+" translated to "+ble.BLEFindInformationResponse(attributes=new_attrs).__repr__())
				packet.attributes=new_attrs
				packet.build()
				return True
			else:
				io.info(packet.__repr__()+" dropped (handle removed)")
				return False
		else:
			for attr in dir(packet):
				if attr in ["handle","endHandle","startHandle","valueHandle"] and not (attr=="endHandle" and packet.endHandle==0xFFFF):
					handle=getattr(packet, attr)
					newHandle=self._translateSingleHandleSlave(handle)
					io.info(handle.__repr__()+" has been replaced by "+newHandle.__repr__())
					setattr(packet,attr,newHandle)
			return True


	def translateHandlesFromMaster(self, packet):
		io.info("Translating from Master : "+packet.__repr__())
		for attr in dir(packet):
			if attr in ["handle","startHandle","endHandle","valueHandle"] and not (attr=="endHandle" and packet.endHandle==0xFFFF):
				handle = getattr(packet, attr)
				newHandle=handle
				for start, end in self.removedHandles:
					if start<=newHandle:
						newHandle+=end-start+1 # end included
					else:
						break
				setattr(packet, attr, newHandle)
				io.info(handle.__repr__()+" has been replaced by "+newHandle.__repr__())
		return True


	def errorResponse(self, packet):
		if type(packet)==ble.BLEReadByTypeRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x08, ecode=ble.ATT_ERR_READ_NOT_PERMITTED, handle=packet.startHandle))
		elif type(packet)==ble.BLEFindInformationRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x04, ecode=ble.ATT_ERR_ATTR_NOT_FOUND, handle=packet.startHandle))
		elif type(packet)==ble.BLEReadByGroupTypeRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x10, ecode=ble.ATT_ERR_ATTR_NOT_FOUND, handle=packet.startHandle))
		elif type(packet)==ble.BLEReadRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x0a, ecode=ble.ATT_ERR_READ_NOT_PERMITTED, handle=packet.handle))
		elif type(packet)==ble.BLEReadBlobRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x0a, ecode=ble.ATT_ERR_READ_NOT_PERMITTED, handle=packet.handle))
		elif type(packet)==ble.BLEWriteRequest:
			self.module.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x12, ecode=ble.ATT_ERR_WRITE_NOT_PERMITTED, handle=packet.handle))


	def connection2addresses(self, packet, fromMaster):
		# returns source and destination addresses for a packet, in the case in came

		cHandle=packet.connectionHandle

		dstAddr=self.module.args["TARGET"]
		srcAddr=self.module.initiatorAddress

		if fromMaster:
			return srcAddr, dstAddr
		else:
			return dstAddr, srcAddr


	# packet handlers
	{2}

	def onStart(self):
		# GATT_FILTER rules
		{4}

		self.runDiscover()
		self.mitmRunning=True

		# BLE_TABLES rules
		try:
			{3}
		except AttributeError as e:
			io.fail("Invalid packet type : "+e.args[0])
			raise
		except KeyError as e:
			io.fail("Unknown attribute name : "+e.args[0])
			raise
		except firewall_rules.IncompatibleAttributeException as e:
			io.fail("Attribute compatibility issue : "+e.args[0])
			raise
		except firewall_rules.InvalidAttributeException as e:
			io.fail("Invalid attribute : "+e.args[0])
			raise
		except Exception as e:
			import traceback
			io.fail("Something went wrong during scenario initialisation :")
			traceback.print_exc()

