import time
import can
import sys
from can.interfaces.interface import Bus
can_interface = 'can0'

#
# TODO: keep sending 700/02 3e 80
# 
#

bus = Bus(can_interface)

receivers = []

def hexdump(x):
	return ' '.join("%02x" % y for y in bytearray(x))

class IsoTp:
	PAD = bytes([0x55])
	def __init__(self, bus, id_source, id_target, add_address_info = None):
		global receivers
		self.id_source = id_source
		self.id_target = id_target
		self.add_address_info = add_address_info
		self.bus = bus
		receivers.append(self)
		self.rx_pdu = None
		self.rx_dl = None
		self.rx_exp_sn = None
		self.debug = True
		
		self.received_pdus = []
		self.received_fctrl = []
	
	def close(self):
		receivers.remove(self)
	
	def send_pdu(self, data):
		prefix = bytes() if self.add_address_info is None else bytes([self.add_address_info])
		
		if self.debug:
			print("IsoTp> SEND PDU", hexdump(data))

		if len(data) <= 8 - 1 - len(prefix):
			frame = prefix + bytes([len(data)]) + data
			frame = frame + self.PAD * (8 - len(frame))
			msg = can.Message(arbitration_id = self.id_source, data = frame, extended_id = False)
			if self.debug:
				print(">", msg)
			self.bus.send(msg)
		else:
			if self.debug:
				print("sending %d bytes" % len(data))
			frame = prefix + bytes([0x10 | (len(data) >> 8), len(data) & 0xFF])
			db = 8-len(frame)
			frame += data[:db]
			frame = frame + self.PAD * (8 - len(frame))
			msg = can.Message(arbitration_id = self.id_source, data = frame, extended_id = False)
			if self.debug:
				print(">", msg)
			self.bus.send(msg)
			data = data[db:]
			
			sn = 1
			
			self.received_fctrl = []
			poll(self.bus, self.received_fctrl)
			
			while len(data):
				frame = prefix + bytearray([0x20 | sn])
				db = 8-len(frame)
				if self.debug:
					print("getting rid of %d" % db)
				frame += data[:db]
				frame = frame + self.PAD * (8 - len(frame))
				msg = can.Message(arbitration_id = self.id_source, data = frame, extended_id = False)
				if self.debug:
					print(">", msg)
				self.bus.send(msg)
				data = data[db:]
				if self.debug:
					print("remaining", hexdump(data))
				sn += 1
				sn &= 0xF
				

	def receive(self, msg):
		if msg.arbitration_id != self.id_target:
			return
		
		if self.debug:
			print("IsoTp> RECEIVE FRAME: ", hexdump(msg.data))
		frame = msg.data
		if self.add_address_info:
			add_address_info = frame[0]
			frame = frame[1:]
		
		frame_type = frame[0] >> 4
		
		if frame_type == 1: # FF
			PCI = frame[:2]
			frame = frame[2:]
		else: # CF/FF
			PCI = frame[:1]
			frame = frame[1:]
	
		if frame_type == 0: # SF
			DL = PCI[0] & 0x0F
			assert len(frame) >= DL
			self.receive_pdu(frame[:DL])
		elif frame_type == 1: # FF
			assert self.rx_pdu is None
			self.rx_pdu = frame
			self.rx_dl = ((PCI[0] & 0xF) << 8) | PCI[1]
			self.rx_exp_sn = 1
			fcmsg = can.Message(arbitration_id = self.id_source, data = bytearray([0x30, 0x00, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55]), extended_id = False)
			self.bus.send(fcmsg)
			if self.debug:
				print("sending flow control message", fcmsg)
		elif frame_type == 2: # CF
			assert self.rx_pdu is not None
			SN = PCI[0]	&0xF
			assert SN == self.rx_exp_sn
			
			self.rx_pdu += frame
			if len(self.rx_pdu) >= self.rx_dl:
				self.receive_pdu(self.rx_pdu[:self.rx_dl])
				self.rx_pdu = None
			else:
				self.rx_exp_sn = (SN + 1) & 0xF
		elif frame_type == 3: # FC
			if self.debug:
				print("got flow control message", hexdump(frame))
			self.received_fctrl.append(frame)
		else:
			assert False, "invalid IsoTp frame type %02x" % frame_type
			
	def receive_pdu(self, pdu):
		if self.debug:
			print("IsoTp> Receive PDU %s" % hexdump(pdu))
		self.received_pdus.append(pdu)
		
	def get_pdu(self):
		while True:
			if not self.received_pdus:
				poll(self.bus, self.received_pdus)
			r = self.received_pdus.pop(0)
			if r[0] == 0x7F and r[2] == 0x78:
				print("pending!")
			else:
				return r

def poll(bus, l):
	while not len(l):
		message = bus.recv()
		for r in receivers:
			r.receive(message)

class UdsException(Exception):
	def __init__(self, error, pdu):
		Exception.__init__(self, error + ": " + hexdump(pdu))
		self.pdu = pdu

class Uds:
	def __init__(self, bus, id_source, id_dest):
		self.tp = IsoTp(bus, id_source, id_dest)

	
	DiagnServi_DiagnSessiContrDevelSessi = 0x4F
	DiagnServi_DiagnSessiContrECUProgrSessi = 0x02
	DiagnServi_DiagnSessiContrExtenDiagnSessi = 0x03
	DiagnServi_DiagnSessiContrOBDIIAndVWDefauSessi = 0x01
	DiagnServi_DiagnSessiContrVWEndOfLineSessi = 0x40

	Req_SecurityAccess = 0x27
	Req_ReadDataByIdent = 0x22
	Resp_DiagnSessiContr = 0x50
	Resp_ReadDataByIdent = 0x62

	def DiagnosticSessionControl(self, LEV):
		self.tp.send_pdu(bytearray([0x10, LEV]))
		result = self.tp.get_pdu()
		if result[0] != self.Resp_DiagnSessiContr:
			raise UdsException("DiagnosticSessionControl failed", result)

	def ReadDataByIdent(self, ident):
		ident = bytearray([(ident >> 8) & 0xFF, ident & 0xFF])
		uds.tp.send_pdu(bytearray([self.Req_ReadDataByIdent]) + ident)
		result = self.tp.get_pdu()
		if result[0] == self.Resp_ReadDataByIdent and result[1:3] == ident:
			return result[3:]
		else:
			return None

	def SecurAccesRequeSeed(self, fnc = 3):
		uds.tp.send_pdu(bytearray([0x27, fnc]))
		result = self.tp.get_pdu()
		if result[0:2] != bytearray([0x67, fnc]):
			raise UdsException("SecurAccesRequeSeed", result)
		return result[2:]

	def SecurAccesResp(self, seed, fnc = 4):
		uds.tp.send_pdu(bytearray([0x27, fnc]) + seed)
		result = self.tp.get_pdu()
		if result[0:2] != bytearray([0x67, fnc]):
			raise UdsException("SecurAccesResp", result)

	def RoutiContrCheckProgrPreco(self):
		uds.tp.send_pdu(bytearray([0x31, 0x01, 0x02, 0x03]))
		res = self.tp.get_pdu()
		if res != bytearray([0x71, 0x01, 0x02, 0x03]):
			raise UdsException("RoutiContrCheckProgrPreco failed", res)
	
	def DiagnServi_ContrDTCSetti(self):
		uds.tp.send_pdu(bytearray([0x85, 0x02, 0xFF, 0xFF, 0xFF]))
		res = self.tp.get_pdu()
		if res != bytearray([0xC5, 0x02]):
			raise UdsException("DiagnServi_ContrDTCSetti failed", res)

	def CommuContr(self, ctrl0, ctrl1):
		uds.tp.send_pdu(bytearray([0x28, ctrl0, ctrl1]))
#		res = self.tp.get_pdu()
#		print "CommuContr", hexdump(res)
#		if res != bytearray([0xC5, 0x02]):
#			raise UdsException("CommuContr failed", res)

uds = Uds(bus, 0x7e0, 0x7e8) # ecu

print(uds.ReadDataByIdent(0xf19e))

import struct

#uds.DiagnosticSessionControl(uds.DiagnServi_DiagnSessiContrExtenDiagnSessi)
#
#def security_access():
#	seed = struct.unpack(">I", uds.SecurAccesRequeSeed(3))[0]
#	resp = seed + 12233
#	uds.SecurAccesResp(struct.pack(">I", resp))
#
#security_access()
#
#uds.DiagnosticSessionControl(uds.DiagnServi_DiagnSessiContrDevelSessi)
#
#security_access()


def read(v, len = 4):
	uds.tp.send_pdu(struct.pack(">BBIH", 0x23, 0x24, v, len))
	r = uds.tp.get_pdu()
	if r[0] == 0x7f and r[2] == 0x31:
		return None
	assert r[0] == 0x63, r
	return r[1:]

def read8(v):
	return struct.unpack("<B", read(v, 1))

def read16(v):
	return struct.unpack("<H", read(v, 2))

def read32(v):
	return struct.unpack("<I", read(v, 4))

