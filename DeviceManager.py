#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os,sys,struct,json
from socket import *
from datetime import *
import hashlib

try: 
	from Tkinter import *
	import ttk
	GUI_TK=True
except:
	GUI_TK=False
try:
	import pygtk
	import gobject
	import gtk
	#import gtk.glade
	import pango
	GUI_GTK=True
except:
	GUI_GTK=False

def get_ip():
	ip = gethostbyname_ex(gethostname())[2][0]
	ipn = struct.unpack(">I",inet_aton(ip))
	return (inet_ntoa(struct.pack(">I",ipn[0]+10)),"255.255.255.0",inet_ntoa(struct.pack(">I",ipn[0]&0xFFFFFF01)))
devices = {}
log = "search.log"
help = """
	Usage: %s [Command];[Command];...
	
	Command			Description
	
	help			This help
	echo			Just echo
	log [filename]		Set log file
	logLevel [0..100]	Set log verbosity
	search [brand]		Searching devices of [brand] or all
	table			Table of devices
	json			JSON String of devices
	device [MAC]		JSON String of [MAC]
	config [MAC] [IP] [MASK] [GATE] [Pasword]   - Configure searched divice
	"""%os.path.basename(sys.argv[0])
def tolog(s):
		logfile = open(log, "a+")
		logfile.write(datetime.now().strftime("[%Y-%m-%d %H:%M:%S] >")+s)
		logfile.close()

def sofia_hash(msg):
	s = ""
	md5 = hashlib.md5(msg).digest()
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

def GetIP(s):
	return inet_ntoa(struct.pack('<I',int(s,16)))

def SetIP(ip):
	return "0x%08X"%struct.unpack('<I',inet_aton(ip))

def SearchXM(devices):
	server = socket(AF_INET, SOCK_DGRAM)
	server.bind(('',34569))
	server.settimeout(1)
	client = socket(AF_INET, SOCK_DGRAM)
	client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	client.sendto('\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x05\x00\x00\x00\x00',("255.255.255.255", 34569))
	while True:
		try:
			data = server.recvfrom(1024)
			typ,leng = struct.unpack('<BxI',data[0][14:20])
			if (typ == 0xfb or data[0][1] == '\x01') and leng > 0:
				answer = json.loads(data[0][20:19+leng],encoding="cp866")
				if not devices.has_key(answer['NetWork.NetCommon']['MAC']):
					devices[answer['NetWork.NetCommon']['MAC']] = answer['NetWork.NetCommon']
					devices[answer['NetWork.NetCommon']['MAC']][u'Brand'] = u"xm"
		except:
			break
	client.close()
	server.close()
	return devices

def SearchDahua(devices):
	server = socket(AF_INET, SOCK_DGRAM)
	server.bind(('',5050))
	server.settimeout(1)
	client = socket(AF_INET, SOCK_DGRAM)
	client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	client.sendto('\xa3\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',("255.255.255.255", 5050))
	while True:
		try:
			data = server.recvfrom(1024)
			if data[0][0] == '\xb3' and len(data[0]) > 137:
				answer = {}
				answer[u'Brand'] = u"dahua"
				info,name = struct.unpack('8s16s',data[0][32:56])
				answer[u'HostName'] = name.replace('\x00','')
				ip,mask,gate,dns,answer[u'TCPPort'] = struct.unpack('<IIII26xH',data[0][56:100])
				answer[u'HostIP'],answer[u'Submask'],answer[u'GateWay'],answer[u'DNS'] = "0x%08X"%ip,"0x%08X"%mask,"0x%08X"%gate,"0x%08X"%dns
				answer[u'MAC'] = data[0][120:137]
				answer[u'Model'] = data[0][137:]
				answer[u'HttpPort'] = 80
				if not devices.has_key(answer[u'MAC']):
					devices[answer[u'MAC']] = answer
		except:
			break
	client.close()
	server.close()
	return devices

def SearchFros(devices):
	client = socket(AF_INET, SOCK_DGRAM)
	client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	client.settimeout(1)
	client.sendto("MO_I\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01", ("255.255.255.255", 10000))
	while True:
		try:
			data = client.recvfrom(1024)
			cmd, legth = struct.unpack('<4xh9xi4x',data[0][:23])
			ser, name = struct.unpack('<13s21s',data[0][23:57])
			ip, mask, gate, dns = struct.unpack('<IIII',data[0][57:73])
			ser = ser.replace('\x00','')
			mac = ser[:2]+':'+ser[2:4]+':'+ser[4:6]+':'+ser[6:8]+':'+ser[8:10]+':'+ser[10:12]
			name = name.replace('\x00','')
			ip,mask,gate,dns = "0x%08X"%ip,"0x%08X"%mask,"0x%08X"%gate,"0x%08X"%dns
			ver, webver = struct.unpack('<4s4s',data[0][77:85])
			ver = ".".join([str(ord(x)) for x in ver])
			webver = ".".join([str(ord(x)) for x in webver])
			if not devices.has_key(mac):
				devices[mac] = { u"Brand":u"fros",u"GateWay" : gate, u"DNS": dns, u"HostIP" : ip, u"HostName" : name, u"HttpPort" : 80, u"TCPPort": 80, u"MAC" : mac, u"MaxBps" : 0, u"MonMode" : u"HTTP", u"SN" : ser, u"Submask" : mask, u"SwVer": ver, u"WebVer": webver }
		except:
			break
	client.close()
	return devices

def ConfigXM(devices, data):
	config = {}
	config[u'DvrMac'] = devices[data[1]][u'MAC']
	config[u'EncryptType'] = 1
	config[u'GateWay'] = SetIP(data[4])
	config[u'HostIP'] = SetIP(data[2])
	config[u'HostName'] = devices[data[1]][u'HostName']
	config[u'HttpPort'] = devices[data[1]][u'HttpPort']
	config[u'MAC'] = devices[data[1]][u'MAC']
	config[u'MaxBps'] = devices[data[1]][u'MaxBps']
	config[u'MonMode'] = devices[data[1]][u'MonMode']
	config[u'SSLPort'] = devices[data[1]][u'SSLPort']
	config[u'Submask'] = SetIP(data[3])
	config[u'TCPMaxConn'] = devices[data[1]][u'TCPMaxConn']
	config[u'TCPPort'] = devices[data[1]][u'TCPPort']
	config[u'TransferPlan'] = devices[data[1]][u'TransferPlan']
	config[u'UDPPort'] = devices[data[1]][u'UDPPort']
	config[u'UseHSDownLoad'] = devices[data[1]][u'UseHSDownLoad']
	config[u'Username'] = "admin"
	config[u'Password'] = sofia_hash(data[5])
	config = json.dumps(config)+"\n"
	server = socket(AF_INET, SOCK_DGRAM)
	server.bind(('',34569))
	server.settimeout(1)
	client = socket(AF_INET, SOCK_DGRAM)
	client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	#('\xff\x00\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc\x05\x8f\x01\x00\x00{ "DvrMac" : "40:16:7E:B1:29:66", "EncryptType" : 1, "GateWay" : "0x0100A8C0", "HostIP" : "0x6E00A8C0", "HostName" : "LocalHost", "HttpPort" : 80, "MAC" : "00:12:16:ec:72:d6", "MaxBps" : 0, "MonMode" : 0, "Password" : "tlJwpbo6", "SSLPort" : 8443, "Submask" : "0x00FFFFFF", "TCPMaxConn" : 10, "TCPPort" : 34567, "TransferPlan" : 1, "UDPPort" : 34568, "UseHSDownLoad" : false, "Username" : "admin" }\n', ('192.168.0.20', 34569))
	client.sendto('\xff\x00\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc\x05'+struct.pack('<i',len(config))+config,("255.255.255.255", 34569))
	print config
	answer = {}
	while True:
		try:
			#('\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfd\x05,\x00\x00\x00{"Ret" : 100, "SessionID" : "0x00000000" }\x00\x00', ('192.168.0.110', 55705))
			data = server.recvfrom(1024)
			print data
			typ,leng = struct.unpack('<BxI',data[0][14:20])
			if (typ == 0xfd or data[0][1] == '\x01') and leng > 0:
				answer = json.loads(data[0][20:19+leng],encoding="cp866")
		except:
			break
			e = 1
	client.close()
	server.close()
	return answer
	
def ConfigFros(devices, data):
	#('MO_I\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x00\x00\x00=\x00\x00\x00\x00\x00\x00\x010001FFBC1113\x00admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00d\xff\xff\xff\x00\xc0\xa8\x00\x01\xc0\xa8\x00\x01\x00P', ('192.168.0.201', 10000))
	#server = socket(AF_INET, SOCK_DGRAM)
	#server.bind(('',10000))
	#server.settimeout(1)
	client = socket(AF_INET, SOCK_DGRAM)
	client.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	client.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	client.sendto(struct.pack('<4sB10xB3xB6xB12sx12sx12sxIIIIxB','MO_I',2,61,61,1,devices[data[1]][u'MAC'].replace(":",""),'admin',data[5],int(SetIP(data[2]),16),int(SetIP(data[3]),16),int(SetIP(data[4]),16),int(SetIP(data[4]),16),80),("255.255.255.255", 10000))
	answer = {}
	while True:
		try:
			#data = server.recvfrom(1024)
			#print data
			data = client.recvfrom(1024)
			#print data
			if data[0][4] == '\x03':
				s, type, n, n, result = struct.unpack('<4sB10xB3xB3xBx',data[0])
				if result == 0:
					answer[u'Result'] = "OK"
				else:
					answer[u'Result'] = "ERROR"
					answer[u'Error'] = result
			break
		except:
			break
			e = 1
	client.close()
	#server.close()
	return answer


def ProcessCMD(cmd):
	global log,logLevel,devices,searchers,configure
	if logLevel >= 20:
		tolog(" ".join(cmd))
	if cmd[0].lower() in ["help","?","/?","-h","--help"]:
		print help
	if cmd[0].lower() == "search":
		if len(cmd) > 1 and searchers.has_key(cmd[1]):
			devices = searchers[cmd[1]](devices)
			print "Searching %s, found %d devices"%(cmd[1],len(devices))
		else:
			for s in searchers:
				logs = "Searching %s"%s
				if logLevel >= 10:
					print logs
				if logLevel >= 20:
					tolog(logs)
				try:
					devices = searchers[s](devices)
				except Exception as error:
					print error
			logs = "Found %d devices"%len(devices)
			if logLevel >= 10:
				print logs
			if logLevel >= 20:
				tolog(logs)
		if len(devices) > 0:
			if logLevel > 0:
				cmd[0] = "table"
				print ""
	if cmd[0].lower() == "table":
		logs = "Vendor\tMAC\t\t\tName\t\tIP\t\tPort"
		print logs
		if logLevel >= 20:
			tolog(logs)
		for dev in devices:
			logs = "%s\t%s\t%s\t%s\t%s"%(devices[dev]['Brand'],devices[dev]['MAC'],devices[dev]['HostName'],GetIP(devices[dev]['HostIP']),devices[dev]['TCPPort'])
			if logLevel >= 20:
				tolog(logs)
			print logs
	if cmd[0].lower() == "json":
		print json.dumps(devices)
	if cmd[0].lower() == "device":
		if len(cmd) > 1 and devices.has_key(cmd[1]):
			print json.dumps(devices[cmd[1]])
		else:
			print "device [MAC]"
	if cmd[0].lower() == "config":
		if len(cmd) > 1 and devices.has_key(cmd[1]):
			print json.dumps(configure[devices[cmd[1]]['Brand']](devices,cmd))
		else:
			print "config [MAC] [IP] [MASK] [GATE] [Pasword]"
	if cmd[0].lower() == "loglevel":
		if len(cmd) > 1:
			logLevel = int(cmd[1])
		else:
			print "loglevel [int]"
	if cmd[0].lower() == "log":
		if len(cmd) > 1:
			log = " ".join(cmd[1:])
		else:
			print "log [filename]"
	if cmd[0].lower() == "echo":
		if len(cmd) > 1:
			print " ".join(cmd[1:])

class GUITk:
	def __init__(self,root):
		self.root=root
		self.root.wm_title("Device Manager")
		self.f = ttk.Frame(self.root)
		self.f.rowconfigure(0, weight=1)
		self.f.columnconfigure(0, weight=1)
		self.f.pack(fill=BOTH, expand=YES)
		#self.f.bind('<Configure>', self.resize)

		self.fr = ttk.Frame(self.f)
		self.fr.pack(fill=BOTH, expand=YES)
		self.fr.rowconfigure(0, weight=1)
		self.fr.columnconfigure(0, weight=1)
		self.fr.grid(row=0, column=0, columnspan=3, sticky="nsew")
		self.fr_tools = ttk.Frame(self.f)
		self.fr_tools.pack(fill=X, expand=YES)
		self.fr_tools.grid(row=1, column=0, columnspan=4, sticky="ew")
		self.fr_config = ttk.Frame(self.f)
		self.fr_config.pack(fill=Y, expand=YES)
		self.fr_config.grid(row=0, column=5, sticky="nsew")

		# Определяем таблицу Treeview
		self.table = ttk.Treeview(self.fr, show='headings', selectmode='browse', height=10)
		self.table.pack(fill=BOTH, expand=YES)
		self.table.grid(column=0, row=0, sticky="nsew")
		# Задаем заголовки колонкам
		self.table["columns"]=("ID","vendor","addr","port","name","mac","cloud")
		# Выводим необходимые столбцы
		self.table["displaycolumns"]=("vendor","addr","port","name","mac","cloud")

		self.table.heading("ID", text=u"ID", anchor='w')
		self.table.heading("vendor", text=u"Производитель", anchor='w')
		self.table.heading("addr", text=u"IP Адресс", anchor='w')
		self.table.heading("port", text=u"Порт", anchor='w')
		self.table.heading("name", text=u"Наименование", anchor='w')
		self.table.heading("mac", text=u"MAC Адрес", anchor='w')
		self.table.heading("cloud", text=u"ИД Облака", anchor='w')

		self.table.column("ID", stretch=0, width=30)
		self.table.column("vendor", stretch=0, width=80)
		self.table.column("addr", stretch=0, width=90)
		self.table.column("port", stretch=0, width=40)
		self.table.column("name", stretch=0, width=90)
		self.table.column("mac", stretch=0, width=95)
		self.table.column("cloud", stretch=0, width=90)


		self.scrollY = ttk.Scrollbar(self.fr, orient=VERTICAL)
		self.scrollY.config(command=self.table.yview)
		self.scrollY.grid(row=0, column=1, sticky="ns")
		self.scrollX = ttk.Scrollbar(self.fr, orient=HORIZONTAL)
		self.scrollX.config(command=self.table.xview)
		self.scrollX.grid(row=1, column=0, sticky="ew")
		self.table.config(yscrollcommand=self.scrollY.set,xscrollcommand=self.scrollX.set)

		self.table.bind('<ButtonRelease>', self.insrec)
		self.table.bind('<Down>', self.insdown)
		self.table.bind('<Up>', self.insup)
		
		self.l1 = ttk.Label(self.fr_config, text="IP Адрес")
		self.l1.grid(row=0, column=0,pady=3,padx=5,sticky=W+N)
		self.addr = ttk.Entry(self.fr_config, width=15, font="6")
		self.addr.grid(row=0, column=1,pady=3,padx=5,sticky=W+N)
		self.l2 = ttk.Label(self.fr_config, text="Маска")
		self.l2.grid(row=1, column=0,pady=3,padx=5,sticky=W+N)
		self.mask = ttk.Entry(self.fr_config, width=15, font="6")
		self.mask.grid(row=1, column=1,pady=3,padx=5,sticky=W+N)
		self.l3 = ttk.Label(self.fr_config, text="Шлюз")
		self.l3.grid(row=2, column=0,pady=3,padx=5,sticky=W+N)
		self.gate = ttk.Entry(self.fr_config, width=15, font="6")
		self.gate.grid(row=2, column=1,pady=3,padx=5,sticky=W+N)
		self.aspc = ttk.Button(self.fr_config, text="Как на ПК",command=self.addr_pc)
		self.aspc.grid(row=3, column=1,pady=3,padx=5,sticky="ew")
		self.l4 = ttk.Label(self.fr_config, text="HTTP порт")
		self.l4.grid(row=4, column=0,pady=3,padx=5,sticky=W+N)
		self.http = ttk.Entry(self.fr_config, width=5, font="6")
		self.http.grid(row=4, column=1,pady=3,padx=5,sticky=W+N)
		self.l5 = ttk.Label(self.fr_config, text="TCP порт")
		self.l5.grid(row=5, column=0,pady=3,padx=5,sticky=W+N)
		self.tcp = ttk.Entry(self.fr_config, width=5, font="6")
		self.tcp.grid(row=5, column=1,pady=3,padx=5,sticky=W+N)
		self.l6 = ttk.Label(self.fr_config, text="Пароль\nadmin")
		self.l6.grid(row=6, column=0,pady=3,padx=5,sticky=W+N)
		self.passw = ttk.Entry(self.fr_config, width=15, font="6")
		self.passw.grid(row=6, column=1,pady=3,padx=5,sticky=W+N)
		self.aply = ttk.Button(self.fr_config, text="Применить",command=self.addr_pc)
		self.aply.grid(row=7, column=1,pady=3,padx=5,sticky="ew")
		self.search = ttk.Button(self.fr_tools, text="Поиск",command=self.search)
		self.search.grid(row=0, column=0,pady=5,padx=5,sticky=W+N)
		self.reset = ttk.Button(self.fr_tools, text="Сброс",command=self.clear)
		self.reset.grid(row=0, column=1,pady=5,padx=5,sticky=W+N)
		self.exp = ttk.Button(self.fr_tools, text="Экспорт",command=self.addr_pc)
		self.exp.grid(row=0, column=2,pady=5,padx=5,sticky=W+N)

	def addr_pc(self):
		_addr,_mask,_gate = get_ip()
		self.addr.delete(0, END)
		self.addr.insert(END, _addr)
		self.mask.delete(0, END)
		self.mask.insert(END, _mask)
		self.gate.delete(0, END)
		self.gate.insert(END, _gate)
	def search(self):
		self.clear()
		ProcessCMD(["search"])
		i=1
		for dev in devices:
			self.table.insert('', 'end', values=(i, devices[dev]['Brand'], GetIP(devices[dev]['HostIP']), devices[dev]['TCPPort'], devices[dev]['HostName'], devices[dev]['MAC'], ""))
			i +=1
	def clear(self):
		global devices
		for i in self.table.get_children():
			self.table.delete(i)
		devices = {}
	def insdown(self, event):
		index = self.table.index(self.table.selection()[0])
		selitem = self.table.selection()[0]
		if self.table.exists(self.table.next(selitem)):
			selitem = self.table.next(selitem)
			index = index+1
			print "Next", self.table.exists(self.table.next(selitem))
		else:
			index = index
			selitem = self.table.focus(selitem)
		print index
	#    print self.table.focus()
	def insup(self, event):
		index = self.table.index(self.table.selection()[0])
		selitem = self.table.selection()[0]
		if int(index)<>0:
			seltext = index-1
			selitem = self.table.prev(selitem)
		if int(index)==0:
			seltext = index
		print seltext
	#    print self.table.selection(seltext)[0]
	def insrec(self, event):
		_mac = self.table.item(self.table.selection()[0], option='values')[5]
		self.addr.delete(0, END)
		self.addr.insert(END, GetIP(devices[_mac]['HostIP']))
		self.mask.delete(0, END)
		self.mask.insert(END, GetIP(devices[_mac]['Submask']))
		self.gate.delete(0, END)
		self.gate.insert(END, GetIP(devices[_mac]['GateWay']))
		self.http.delete(0, END)
		self.http.insert(END, devices[_mac]['HttpPort'])
		self.tcp.delete(0, END)
		self.tcp.insert(END, devices[_mac]['TCPPort'])
		# Вывод ID строки
		print self.table.index(self.table.selection()[0])
	def resize (self, event): 
		print '(% d,% d)'% (event.width, event.height) 
		#self.f.configure (width = event.width-4, height = event.height-4) 

searchers = {"xm":SearchXM,"dahua":SearchDahua,"fros":SearchFros}
configure = {"xm":ConfigXM,"fros":ConfigFros}#,"Dahua":ConfigDahua
logLevel = 10
if __name__ == "__main__":
	if len(sys.argv) > 1:
		cmds = " ".join(sys.argv[1:])
		if cmds.find("-q ") != -1:
			cmds = cmds.replace("-q ","")
			logLevel = 0
		for cmd in cmds.split(";"):
			ProcessCMD(cmd.split(" "))
		sys.exit(1)
	
	if GUI_GTK:
		print "no gtk"
	if GUI_TK:
		root = Tk()
		app = GUITk(root)
		#Style = ttk.Style()
		#ttk.Style.theme_use(Style, "clam")
		root.mainloop()
		sys.exit(1)
	print "Type help or ? to display help(q or Q to exit)"
	while True:
		data = raw_input("> ").split(";")
		for cmd in data:
			if (cmd.lower() == 'q' or cmd.lower() == 'quit'):
				sys.exit(1)
			ProcessCMD(cmd.split(" "))
	sys.exit(1)
