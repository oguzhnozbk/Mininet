#!/usr/bin/python
# -*-coding:utf-8-*-

import threading
import time
from scapy.all import *
from scapy.contrib.openflow3 import *
from Tkinter import *


class MyThreadingClass(threading.Thread):

	def __init__(self, fonk):
		self.t = threading.Thread(target=fonk)

	def startThread(self):
		try:
			self.t.start()
		except Exception as e:
			pass	
	def stopThread(self):
		try:
			self.t.join(1)
		except Exception as e:
			pass

	def isAliveThread(self):
		if self.t.is_alive():
			return True
		else:
			return False


class PingInterfaces(object):

	def __init__(self, master, host, hosts):
		self.top = Toplevel(master)
		self.host = host
		self.hosts = hosts
		self.options = []

		Label(self.top, text="Cihaz Adı: ").grid(row=0, column=0, sticky=E)
		Label(self.top, text=self.host.name).grid(row=0, column=1, sticky=W)

		Label(self.top, text="Cihaz Ip Adresi :").grid(
			row=1, column=0, sticky=E)
		Label(self.top, text=self.host.IP()).grid(row=1, column=1, sticky=W)

		Label(self.top, text="Hedef Cihaz :").grid(row=2, column=0, sticky=E)
		count = 0
		for x in self.hosts:
			if x.name != self.host.name:
				self.options.insert(count, x.IP())
				count += 1
		self.selectionHostIp = StringVar(self.top)
		for x in self.options:
			if x != self.host.name:
				self.selectionHostIp.set(x)
				break
		OptionMenu(self.top, self.selectionHostIp, *
				   (self.options)).grid(row=2, column=1, sticky=W)

		Label(self.top, text="Ping Sayısı : ").grid(row=3, column=0, sticky=E)
		self.pingEntry = StringVar(self.top, value='1')
		Entry(self.top, textvariable=self.pingEntry).grid(
			row=3, column=1, sticky=W)

		Button(self.top, text="TAMAM", width=8, relief='raised', bd=4,
			   bg='lightgrey', command=self.okButton).grid(row=4, column=0, sticky='nswe')
		Button(self.top, text="ÇIK", width=8, relief='raised', bd=4, bg='lightgrey',
			   command=self.quitButton).grid(row=4, column=1, sticky='nswe')
	
	def sendPing(self):
		self.host.cmd('ping -c %s %s' %(self.pingEntry.get(),self.selectionHostIp.get()))
	
	def okButton(self):
		pingThread = MyThreadingClass(fonk = self.sendPing)
		pingThread.startThread()
		pingThread.stopThread()
		self.top.destroy()
		

	def quitButton(self):
		self.top.destroy()


class FlowsOnSwitch(object):

	def __init__(self, master, switch):
		self.top = Toplevel(master)
		self.switch = switch
		self.textLabel=StringVar()

		Label(self.top,textvariable=self.textLabel,bd=8,font="bold").pack(side = TOP,fill=X)

		self.canvas = Canvas(self.top,height = 350)
		
		self.top.bind("<Destroy>",self.quit)

		self.ovsDumpFlows()


	def quit(self,event):
		self.top.destroy()
		
	def ovsDumpFlows(self):

		flows = StringVar()
		flows = self.switch.cmd("ovs-ofctl -O OpenFlow13 dump-flows %s" %self.switch.name)
		self.textLabel.set(self.switch.name+" Switchinde Bulunan "+str(flows.count('cookie'))+" adet akış vardır.")
		self.canvas.frame = Frame(master = self.top,width=10000)
		self.canvas.frame.pack(fill=X)
		self.canvas.xscrollbar = Scrollbar(master=self.top)
		self.canvas.xscrollbar.pack(side="bottom",fill=X)
		self.canvas.xscrollbar.configure(orient="horizontal", command = self.canvas.xview)
		self.canvas.configure(xscrollcommand=self.canvas.xscrollbar.set)
		self.canvas.pack()
		self.canvas.create_window((4,4),window = self.canvas.frame,anchor="nw")
		self.canvas.frame.bind("<Configure>",self.canvas.configure(scrollregion=self.canvas.bbox("all")))

		flows = flows.splitlines()

		for x in flows:
			text = Text(self.canvas.frame,height=19,width=36)
			text.pack(side=LEFT)
			x = x.replace(",","\n")
			text.insert(END,x)

	
class TablesOnSwitch(object):
	
	def __init__(self,master,switch):
		self.top = Toplevel(master)
		self.top.geometry("400x400")
		self.switch = switch

		Label(self.top,text=self.switch.name+" Switchinde Bulunan Tablolar",bd =8,font="bold").pack(side = TOP,fill=X)
		self.textTables = Text(self.top,height=300,width=300)
		self.textTables.pack(side='bottom')

		self.top.bind("<Destroy>",self.quit)
		self.ovsDumpTables()
		
	def quit(self,event):
		self.top.destroy()

	def ovsDumpTables(self):
		tables = StringVar()
		tables = self.switch.cmd("ovs-ofctl -O OpenFlow13 dump-tables %s" %self.switch.name)
		self.textTables.insert(END,tables)
			

class SniffingOnLink(object):

	def __init__(self,master,link):
		self.top = Toplevel(master)

		self.interfaces = []
		if link.intf1.name[0] != 'h':
			self.interfaces.append(link.intf1.name)
		else:
			self.interfaces.append(link.intf2.name)

		Label(self.top, text = link.intf1.node.name + " - " + link.intf2.node.name + " arasındaki ağ trafiği, iface = " + str(self.interfaces)).pack()

		frame = Frame(self.top)
		frame.pack()

		self.count = 0
		self.timer = 0.0
		self.packets = {}

		self.listNodes = Listbox(frame,width=125,height=25,font=("Helvetica", 12))
		self.listNodes.pack(side=LEFT,fill=Y)

		listNodesScrollbar = Scrollbar(frame,orient="vertical")
		listNodesScrollbar.config(command=self.listNodes.yview)
		listNodesScrollbar.pack(side=RIGHT,fill=Y)

		self.listNodes.config(yscrollcommand=listNodesScrollbar.set)
		self.listNodes.bind('<Double-Button-1>',self.showToPacketDetail) 

		self.sniffThread = MyThreadingClass(fonk = self.sniffFunction)
		self.sniffThread.startThread()
		self.sniffStopFilter = threading.Event()
		self.sniffStopThread = MyThreadingClass(fonk = self.sniffStopFunction)

		self.top.bind("<Destroy>",self.quit)

	def sniffFunction(self):
		sniff(iface = self.interfaces, stop_filter = lambda p: self.sniffStopFilter.is_set(), prn=self.networkTrafic, filter="icmp or arp or tcp port 6653")
		

	def networkTrafic(self,packet):
		if self.timer == 0.0:
			self.timer = packet.time
		ptime = packet.time - self.timer
		aPacket = {
		'count' : self.count,
		'time' : ptime,
		'packet' : packet
		}
		self.packets.update({self.count : aPacket})
		self.addToListNodes(aPacket = aPacket)
		self.count +=1

	def addToListNodes(self, aPacket):
		try:
			self.listNodes.insert(aPacket['count'],str(aPacket['count'])+" -- "+str(aPacket['time'])+"  --->  "+aPacket['packet'].summary())
			self.listNodes.see(END)
		except Exception as e:
			pass
		

	def showToPacketDetail(self,event = None):
		selectionPacket = self.listNodes.selection_get()
		selectionPacketCount = int((selectionPacket.split(" "))[0])
		top = Toplevel(self.top)
		selectionPacketDetailTextBox = Text(top,width=60,height=50)
		selectionPacketDetailTextBox.pack()
		selectionPacketDetailTextBox.insert(END,self.packets[selectionPacketCount]['packet'].show(dump=True))

	def sniffStopFunction(self):
		self.sniffStopFilter.set()
		while True:
			self.sniffThread.stopThread()
			if self.sniffThread.isAliveThread():
				pass
			else:
				break

	def quit(self,event):
		self.sniffStopThread.startThread()
		self.top.destroy()

class ControllerSniffingOnLink(object):

	def __init__(self,master,name,port):
		self.top = Toplevel(master)

		self.filter = "tcp port 6653 and tcp port "+str(port)
		
		Label(self.top, text = "Controller ve "+name+" switch'i arasındaki haberleşme. " + self.filter).pack()
		
		frame = Frame(self.top)
		frame.pack()

		self.count = 0
		self.timer = 0.0
		self.e = 0
		self.packets = {}

		self.listNodes = Listbox(frame,width=125,height=25,font=("Helvetica", 12))
		self.listNodes.pack(side=LEFT,fill=Y)

		listNodesScrollbar = Scrollbar(frame,orient="vertical")
		listNodesScrollbar.config(command=self.listNodes.yview)
		listNodesScrollbar.pack(side=RIGHT,fill=Y)

		self.listNodes.config(yscrollcommand=listNodesScrollbar.set)
		self.listNodes.bind('<Double-Button-1>',self.showToPacketDetail) 

		self.sniffThread = MyThreadingClass(fonk = self.sniffFunction)
		self.sniffThread.startThread()
		self.sniffStopFilter = threading.Event()
		self.sniffStopThread = MyThreadingClass(fonk = self.sniffStopFunction)

		self.top.bind("<Destroy>",self.quit)

	def sniffFunction(self):
		sniff(iface = "lo", stop_filter = lambda p: self.sniffStopFilter.is_set(), prn=self.networkTrafic, filter=self.filter)
		

	def networkTrafic(self,packet):
		if self.timer == 0.0:
			self.timer = packet.time
		ptime = packet.time - self.timer
		aPacket = {
		'count' : self.count,
		'time' : ptime,
		'packet' : packet
		}
		if self.e == 0 and packet.sniffed_on == "lo":
			if packet.summary().find("OFPT")>0:
				self.packets.update({self.count : aPacket})
				self.addToListNodes(aPacket = aPacket)
				self.count += 1
			self.e = 1
		elif self.e == 1 and packet.sniffed_on =="lo":
			self.e = 0
		

	def addToListNodes(self, aPacket):
		try:
			self.listNodes.insert(aPacket['count'],str(aPacket['count'])+" -- "+str(aPacket['time'])+"  --->  "+aPacket['packet'].summary())
			self.listNodes.see(END)
		except Exception as e:
			pass
		
	def showToPacketDetail(self,event = None):
		selectionPacket = self.listNodes.selection_get()
		selectionPacketCount = int((selectionPacket.split(" "))[0])
		top = Toplevel(self.top)
		selectionPacketDetailTextBox = Text(top,width=60,height=50)
		selectionPacketDetailTextBox.pack()
		selectionPacketDetailTextBox.insert(END,self.packets[selectionPacketCount]['packet'].show(dump=True))

	def sniffStopFunction(self):
		self.sniffStopFilter.set()
		while True:
			self.sniffThread.stopThread()
			if self.sniffThread.isAliveThread():
				pass
			else:
				break

	def quit(self,event):
		self.sniffStopThread.startThread()
		self.top.destroy()


class SniffingOnAllNetwork(object):
	
	def __init__(self, master,net):
		self.master = master
		self.net = net
		self.timer = None
		self.count = 0
		self.e = 0 

		self.changeColorLink = None
		self.master.listNodes.delete(0,END)
		

		self.sniffThread = MyThreadingClass(fonk = self.sniffFunction)
		self.sniffThread.startThread()
		self.sniffStopFilter = threading.Event()
		self.sniffStopThread = MyThreadingClass(fonk = self.sniffStopFunction)

	def sniffFunction(self):
		interfaces = self.interfacesFind()
		sniff(iface = interfaces, stop_filter = lambda p:self.sniffStopFilter.is_set(), prn=self.allNetworkTraffic, filter="icmp or arp or tcp port 6653")

	def interfacesFind(self):
		interfaces = []
		for link in self.net.links:
			if link.intf1.name[0] != 'h':
				interfaces.append(link.intf1.name)
			else:
				interfaces.append(link.intf2.name)
		interfaces.append('lo')
		return interfaces

	def allNetworkTraffic(self,packet):
		commit = None
		if packet.sniffed_on == "lo":
			commit = "CS"
		if commit == None:
			for link in self.net.links:
				if link.intf1.name == packet.sniffed_on:
					if link.intf2.name[0] == 's':
						commit = "SS"
		if commit == None:
			commit = "SH"

		if self.timer == None:
			self.timer = packet.time

		ptime = packet.time - self.timer

		aPacket = {
		'count' : self.count,
		'commit' : commit,
		'time' : ptime,
		'packet' : packet
		}
		if self.e == 0 and packet.sniffed_on == "lo":
			if packet.summary().find("OFPT")>0:
				self.master.packets.update({self.count : aPacket})
				self.master.addToListNodes(aPacket = aPacket)
				self.count += 1
			self.e = 1
		elif self.e == 1 and packet.sniffed_on =="lo":
			self.e = 0
		else:
			self.master.packets.update({self.count : aPacket})
			self.pingWay(packet = packet)
			self.count += 1
			self.master.addToListNodes(aPacket = aPacket)
		
	def pingWay(self,packet):
		if packet.summary().find("ICMP")>0:
			for link in self.net.links:
				if link.intf1.name == packet.sniffed_on:
					break
				elif link.intf2.name == packet.sniffed_on:
					break
			for linksDetail in self.master.links:
				linkDetail = self.master.links[linksDetail]
				src, dst =linkDetail['src'], linkDetail['dest']
				srcName, dstName = src['text'], dst['text']
				if (str(link.intf1.node) == srcName and str(link.intf2.node) == dstName) or (str(link.intf2.node) == srcName and str(link.intf1.node) == dstName):
					break
			self.changeColorLink = linksDetail
			self.pigwayThread = MyThreadingClass(fonk = self.pingWayChangeColor).startThread()
		else:
			pass

	def pingWayChangeColor(self):
		Link = self.changeColorLink
		self.master.canvas.itemconfig(Link,fill='orange')
		time.sleep(1)
		self.master.canvas.itemconfig(Link,fill='blue')

	def sniffStopFunctionStart(self):
		self.sniffStopThread.startThread()
		
	def sniffStopFunction(self):
		self.sniffStopFilter.set()
		while True:
			self.sniffThread.stopThread()
			if self.sniffThread.isAliveThread():
				pass
			else:
				break

class DoStepByStep(object):
	"""docstring for DoStepByStep"""
	def __init__(self, master, packets, canvas,icon,coordinate):
		self.top = Toplevel(master)
		self.packets = self.sortedPacketList(packets)
		#self.packets = packets
		self.canvas = canvas
		self.img = icon
		self.CoControllers, self.CoSwitches,self.CoHosts,self.Colinks = self.partitionNodeCoordinate(coordinate)

		self.slowerCount = StringVar(self.top, value='1000')
		self.packetCount = 0

		self.stopEvent = threading.Event()


		button = self.createButton()
		button.grid(row=0,column=0)
		listbox = self.createListbox()
		listbox.grid(row = 1, column=0)
		
		
		self.addToListNodes()

	#ListBox Framini oluşturur.
	def createListbox(self):
		frame = Frame(self.top)
		
		self.listNodes = Listbox(frame,width=125,height=10,font=("Helvetica", 12))
		self.listNodes.pack(side=LEFT,fill=Y)

		listNodesScrollbar = Scrollbar(frame,orient="vertical")
		listNodesScrollbar.config(command=self.listNodes.yview)
		listNodesScrollbar.pack(side=RIGHT,fill=Y)

		self.listNodes.config(yscrollcommand=listNodesScrollbar.set)
		self.listNodes.bind('<<ListboxSelect>>', self.onSelect)
		self.listNodes.bind('<Double-Button-3>',self.showToPacketDetail)
		self.listNodes.bind('<Double-Button-1>',self.onDoubleButtonSelect)

		return frame  

	#Buttonların bulunduğu Framei oluşturur.
	def createButton(self):
		frame = Frame(self.top)
		
		Button(frame,image=self.img[0], text="Start",command=self.doStart).grid(row = 0, column=0)
		Button(frame,image=self.img[1], text="Pause",command=self.doPause).grid(row = 0, column=4)
		Button(frame,image=self.img[2], text="Stop",command=self.doStop).grid(row = 0, column=2)
		Button(frame,image=self.img[3], text="Next Step",command=self.doNextStep).grid(row = 0, column=8)
		Button(frame,image=self.img[4], text="Back Step",command=self.doBackStep).grid(row = 0, column=6)
		
		Entry(frame, textvariable=self.slowerCount).grid(row=0, column=10, sticky=E)
		Label(frame,text=" Kat yavaşlatılmıştır. ").grid(row = 0,column=11)
		Label(frame,text="  ").grid(row = 0,column=1)
		Label(frame,text="  ").grid(row = 0,column=3)
		Label(frame,text="  ").grid(row = 0,column=5)
		Label(frame,text="  ").grid(row = 0,column=7)
		Label(frame,text="  ").grid(row = 0,column=9)
		Label(frame,text="          ").grid(row = 0,column=12)

		Button(frame,text="İlk ICMP mesajını bul",command=self.doIcmp).grid(row=0,column=13)	
		Button(frame,text="İlk ARP mesajını bul",command=self.doArp).grid(row=0,column=14)	


		frame.bind("<Button-4>", self.mouseWheel)
		frame.bind("<Button-5>", self.mouseWheel)
		

		return frame
	
	#Mause Scroll u ile hızlandırma ve yavaşlatma yapmak için kullanılan fonksiyon
	def mouseWheel(self,event=None):
		count = int(self.slowerCount.get())
		if event.num == 5:
			count -= 100
			if count <= 0:
				count = 1 
		if event.num == 4:
			if count == 1:
				count = 100
			else:
				count += 100
		self.slowerCount.set(count)

	#Mause sol tik ile paket seçme
	def onSelect(self,event=None):
		w = event.widget
		self.packetCount = int(w.curselection()[0])

	#Mause sol çif tikla detay bilgisini görmek istediğimiz paketi açma
	def onDoubleButtonSelect(self, event=None):
		w = event.widget
		self.packetCount = int(w.curselection()[0])
		self.findPacketCoorAndDraw()

	#Detay bilgisini ekrana yazdirma
	def showToPacketDetail(self,event=None):
		w = event.widget
		idx = int(w.curselection()[0])
		top = Toplevel(self.top)
		selectionPacketDetailTextBox = Text(top,width=60,height=50)
		selectionPacketDetailTextBox.pack()
		selectionPacketDetailTextBox.insert(END,self.packets[idx]['packet'].show(dump=True))
	
	#Paketleri zamana göre sıralamayı sağlar
	def sortedPacketList(self,packets):
		newlist = sorted(packets.items(),key = select)
		newPacket = {}
		x = 0
		for packet in newlist:
			newPacket.update({x : {'commit':packet[1]['commit'],'time' : packet[1]['time'],'packet' : packet[1]['packet']}})
			x+=1
		return newPacket
		
	#Listboxa verileri ekler.
	def addToListNodes(self):
		for packet in self.packets:
			self.listNodes.insert(packet,str(packet)+" -- "+str(self.packets[packet]['time'])+"  --->  "+self.packets[packet]['packet'].summary()),

	def partitionNodeCoordinate(self,coor):
		controllers = []
		switches = []
		hosts = []
		links = []
		for co in coor:
			if 'controllers' == co:
				controllers = coor[co]
			if 'hosts' == co:
				hosts = coor[co]
			if 'switches' == co:
				switches = coor[co]
			if 'links' == co:
				links = coor[co]
		return controllers,switches,hosts,links

	def doStart(self):
		MyThreadingClass(fonk = self.start).startThread()

	def start(self):
		self.stopEvent.clear()
		for x in xrange(self.packetCount,len(self.packets)):
			if self.stopEvent.is_set():
				break
			self.listNodes.activate(self.packetCount)
			self.listNodes.see(self.packetCount)
			self.findPacketCoorAndDraw()
			self.packetCount +=1


	def doPause(self):
		self.stopEvent.set()

	def doStop(self):
		self.stopEvent.set()
		self.packetCount = 0
		self.listNodes.activate(self.packetCount)
		self.listNodes.see(self.packetCount)
			
	def doNextStep(self):
		if (len(self.packets)-1) > self.packetCount:
			self.packetCount += 1 
		self.listNodes.activate(self.packetCount)
		self.listNodes.see(self.packetCount)	
		self.findPacketCoorAndDraw()

	def doBackStep(self):
		if self.packetCount > 0:
			self.packetCount -=1
		self.listNodes.activate(self.packetCount)
		self.listNodes.see(self.packetCount)
		self.findPacketCoorAndDraw()
	
	def doIcmp(self):
		for packet in self.packets:
			if self.packets[packet]['packet'].summary().find("ICMP")>0:
				break
		self.packetCount = packet
		self.listNodes.activate(self.packetCount)
		self.listNodes.see(self.packetCount)

	def doArp(self):
		for packet in self.packets:
			if self.packets[packet]['packet'].summary().find("ARP")>0:
				break
		self.packetCount = packet
		self.listNodes.activate(self.packetCount)
		self.listNodes.see(self.packetCount)

	def findPacketCoorAndDraw(self):
		packet = self.packets[self.packetCount]
		data = packet['packet'].summary()
		srcx = None
		srcy = None
		dstx = None
		dsty = None
		if packet['packet'].sniffed_on == "lo":
			if packet['packet'][TCP].sport == 6653:
				for controller in self.CoControllers:
					if controller['port'] == 6653:
						break
				for switch in self.CoSwitches:
					if switch['port'] == str(packet['packet'][TCP].dport):
						break
				srcx = controller['x']
				srcy = controller['y']
				dstx = switch['x']
				dsty = switch['y']
			elif packet['packet'][TCP].dport == 6653:
				for controller in self.CoControllers:
					if controller['port'] == 6653:
						break
				for switch in self.CoSwitches:
					if switch['port'] == str(packet['packet'][TCP].sport):
						break
				srcx = switch['x']
				srcy = switch['y']
				dstx = controller['x']
				dsty = controller['y']
		if packet['commit'] == 'SH':
			try:
				hostName =None
				sName = None
				for link in self.Colinks:
					if packet['packet'].sniffed_on == link['linkName']:
						break
				if link['src'][0]=='h':
					hostName = link['src']
					sName = link['dest']
				else:
					sName = link['src']
					hostName = link['dest']

				for host in self.CoHosts:
					if host['name'] == hostName:
						break
				for switch in self.CoSwitches:
					if switch['name']==sName:
						break
				if str(packet['packet'].getlayer(IP).src) == str(host['ip']):
					srcx = host['x']
					srcy = host['y']
					dstx = switch['x']
					dsty = switch['y']
				elif str(packet['packet'].getlayer(IP).dst) == str(host['ip']):
					srcx = switch['x']
					srcy = switch['y']
					dstx = host['x']
					dsty = host['y']	
			except Exception as e:
				hostName =None
				sName = None
				srchostip=str(packet['packet'].getlayer(ARP).psrc)
				for link in self.Colinks:
					if packet['packet'].sniffed_on == link['linkName']:
						break
				if link['src'][0]=='h':
					hostName = link['src']
					sName = link['dest']
				else:
					sName = link['src']
					hostName = link['dest']

				for host in self.CoHosts:
					if host['name'] == hostName:
						break
				for switch in self.CoSwitches:
					if switch['name']==sName:
						break
				for h in self.CoHosts:
					if str(h['ip'])==srchostip:
						break
				if distance(hostName,h['name'],self.Colinks)<distance(sName,h['name'],self.Colinks):
					srcx = host['x']
					srcy = host['y']
					dstx = switch['x']
					dsty = switch['y']
				else:
					srcx = switch['x']
					srcy = switch['y']
					dstx = host['x']
					dsty = host['y']
			
		if packet['commit'] == 'SS':
			try:
				srchostip=str(packet['packet'].getlayer(IP).src)
				srcSwitch = None
				destSwitch = None
				for link in self.Colinks:
					if packet['packet'].sniffed_on == link['linkName']:
						break
				for host in self.CoHosts:
					if str(host['ip']) == srchostip:
						break
				for switch in self.CoSwitches:
					if switch['name']==link['src']:
						srcSwitch = switch
					if switch['name']==link['dest']:
						destSwitch = switch

				if distance(link['src'],host['name'],self.Colinks)<distance(link['dest'],host['name'],self.Colinks):
					srcx = srcSwitch['x']
					srcy = srcSwitch['y']
					dstx = destSwitch['x']
					dsty = destSwitch['y']
				else:
					srcx = destSwitch['x']
					srcy = destSwitch['y']
					dstx = srcSwitch['x']
					dsty = srcSwitch['y']

			except Exception as e:
				srchostip=str(packet['packet'].getlayer(ARP).psrc)
				srcSwitch = None
				destSwitch = None
				for link in self.Colinks:
					if packet['packet'].sniffed_on == link['linkName']:
						break
				for host in self.CoHosts:
					if str(host['ip']) == srchostip:
						break
				for switch in self.CoSwitches:
					if switch['name']==link['src']:
						srcSwitch = switch
					if switch['name']==link['dest']:
						destSwitch = switch

				if distance(link['src'],host['name'],self.Colinks)<distance(link['dest'],host['name'],self.Colinks):
					srcx = srcSwitch['x']
					srcy = srcSwitch['y']
					dstx = destSwitch['x']
					dsty = destSwitch['y']
				else:
					srcx = destSwitch['x']
					srcy = destSwitch['y']
					dstx = srcSwitch['x']
					dsty = srcSwitch['y']


		if srcx != None:
			self.drawPacket(float(srcx),float(srcy),float(dstx),float(dsty),data)


	def drawPacket(self,srcx,srcy,dstx,dsty,data):
		coord = [srcx-7,srcy-7,srcx+7,srcy+7]
		circle = self.canvas.create_oval(coord,outline="red",fill="red")
		packetSummary = self.canvas.create_text(srcx-20,srcy-14,text = data)
		sleepTime = 0.001*int(self.slowerCount.get())
		
		for x in xrange(1,100):
			newCoordX = (dstx-srcx)/100
			newCoordY = (dsty-srcy)/100
			self.canvas.move(circle,newCoordX,newCoordY)
			self.canvas.move(packetSummary,newCoordX,newCoordY)
			self.canvas.update()
			time.sleep(sleepTime/100)
		self.canvas.delete(circle)
		self.canvas.delete(packetSummary)
		self.canvas.update()

def select(packet):
	p = packet[1]
	return p['time']

def distance(location,targetLocation,links):
	liste = []
	for x in links:
		liste.append(x['src'])
		liste.append(x['dest'])
	a=True
	while a:
		for x in liste:
			if liste.count(x)>1:
				liste.remove(liste[liste.index(x)])
		a = False
		for x in liste:
			if liste.count(x)>1:
				a = True
	k = {}
	for lis in liste:
		h = []
		for link in links:
			if link['src'] == lis:
				h.append(link['dest'])
			if link['dest'] == lis:
				h.append(link['src'])
		k.update({lis : h })
	return function(location,targetLocation,k)

def function(sr , ds , lis):
	if lis[sr].count(ds) == 1:
		return 1
	src = []
	for x in lis[sr]:
		if x[0] =='s':
			src.append(x)
	if len(src) == 0:
		return "e"
	newlis = {}
	for x in lis:
		if x != sr:
			s =[]
			for a in lis[x]:
				if a != sr:
					s.append(a)
			newlis.update({x:s})
	for x in src:
		try:
			return 1 + function(x,ds,newlis)
		except Exception as e:
			pass