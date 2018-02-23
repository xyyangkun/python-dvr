#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os,sys,struct,json
from time import sleep
import hashlib
import threading
from socket import *
from datetime import *

class DVRIPCam(object):
	DATE_FORMAT="%Y-%m-%d %H:%M:%S"
	CODES = {
		100 : "OK",
		101 : "Unknown error",
		102 : "Unsupported version", 
		103 : "Request not permitted", 
		104 : "User already logged in",
		105 : "User is not logged in",
		106 : "Username or password is incorrect",
		107 : "User does not have necessary permissions",
		203 : "Password is incorrect",
		515 : "Upgrade successful"
	}
	QCODES = {
		"KeepAlive":1006,
		"OPTimeQuery":1452,
		"OPTimeSetting":1450,
		"OPMailTest":1636,
		#{ "Name" : "OPMailTest", "OPMailTest" : { "Enable" : true, "MailServer" : { "Address" : "0x00000000", "Anonymity" : false, "Name" : "Your SMTP Server", "Password" : "", "Port" : 25, "UserName" : "" }, "Recievers" : [ "", "none", "none", "none", "none" ], "Schedule" : [ "0 00:00:00-24:00:00", "0 00:00:00-24:00:00" ], "SendAddr" : "", "Title" : "Alarm Message", "UseSSL" : false }, "SessionID" : "0x1" }
		"OPMachine":1450,
		"OPMonitor":1413,
		"OPTalk":1434,
		"SystemFunction":1360,
		"EncodeCapability":1360
	}
	OK_CODES = [100,515]
	def __init__(self, ip, user="admin", password= "", port = 34567):
		self.ip = ip
		self.user = user
		self.password = password
		self.port = port
		self.socket = None
		self.packet_count = 0
		self.session = 0
		self.alive = None
		self.alive_time = 20
	def connect(self):
		self.socket = socket(AF_INET, SOCK_STREAM)
		self.socket.connect((self.ip, self.port))
	def close(self):
		self.alive.cancel()
		self.socket.close()
		self.socket = None
	def send(self, msg, data):
		if self.socket == None:
			return {"Ret":101}
		if hasattr(data, '__iter__'):
			data = json.dumps(data, ensure_ascii=False).encode('utf8')
		self.socket.send(struct.pack('BB2xII2xHI',255, 0, self.session, self.packet_count, msg ,len(data)+2)+data+"\x0a\x00")
		try:
			head, version, self.session, sequence_number, msgid, len_data = struct.unpack('BB2xII2xHI',self.socket.recv(20))
			sleep(.1)#Just for recive whole packet
			reply = self.socket.recv(len_data)
			self.packet_count += 1
			reply = json.loads(reply[:-2],encoding="utf8")
			return reply
		except:
			return {"Ret":101}
		
	def sofia_hash(self, password):
		s = ""
		md5 = hashlib.md5(password).digest()
		for n in range(8):
			c = (ord(md5[2*n])+ord(md5[2*n+1]))%62
			if c > 9:
				if c > 35:
					c += 61
				else:
					c += 55
			else:
				c += 48
			s += chr(c)
		return s
	def login(self):
		if self.socket == None:
			self.connect()
		data = self.send(1000,{"EncryptType":"MD5","LoginType":"DVRIP-Web","PassWord":self.sofia_hash(self.password),"UserName":self.user})
		self.session = int(data["SessionID"],16)
		self.alive_time = data["AliveInterval"]
		self.keep_alive()
		return data["Ret"] in self.OK_CODES
	def reboot(self):
		self.set(self.QCODES["OPMachine"],"OPMachine",{ "Action" : "Reboot" })
		self.close()
	def pretty_print(self, data):
		print json.dumps(data, indent = 4, sort_keys = True)
	def keep_alive(self):
		self.send(self.QCODES["KeepAlive"],{"Name":"KeepAlive","SessionID":"0x%08X"%self.session})
		self.alive = threading.Timer(self.alive_time, self.keep_alive)
		self.alive.start()
	def set_info(self, command, data):
		return self.set(1040, command, data)
	def set(self, code, command, data):
		return self.send(code, {"Name":str(command),"SessionID":"0x%08X"%self.session,str(command):data})
	def get_info(self, command):
		return self.get(1042, command)
	def get(self, code, command):
		data = self.send(code, {"Name":str(command),"SessionID":"0x%08X"%self.session})
		if data["Ret"] in self.OK_CODES:
			return data[str(command)]
		else:
			return data
	def get_time(self):
		return datetime.strptime(self.get(QCODES["OPTimeQuery"],"OPTimeQuery"),self.DATE_FORMAT)
	def set_time(self, time=None)
		if time==None:
			time=datetime.now()
		return self.set(QCODES["OPTimeSetting"],"OPTimeSetting",time.strftime(self.DATE_FORMAT))
	def get_system_info(self):
		data = self.get(1042, "General")
		self.pretty_print(data)
		
	def get_encode_capabilities(self):
		data = self.get(self.QCODES["EncodeCapability"], "EncodeCapability")
		self.pretty_print(data)
	
	def get_system_capabilities(self):
		data = self.get(self.QCODES["SystemFunction"], "SystemFunction")
		self.pretty_print(data)
	
	def get_camera_info(self, default = False):
		"""Request data for 'Camera' from  the target DVRIP device."""
		if default:
			code = 1044
		else:
			code = 1042
		data = self.get_info(code, "Camera")
		self.pretty_print(data)
		
	def get_encode_info(self, default = False):
		"""Request data for 'Simplify.Encode' from the target DVRIP device.

			Arguments:
			default -- returns the default values for the type if True

		"""

		if default:
			code = 1044
		else:
			code = 1042

		data = self.get_info(code, "Simplify.Encode")
		self.pretty_print(data)
