import dpkt
import socket
import datetime
import time
import math
import sys
import numpy as np
#from collections import OrderedDict

if(len(sys.argv) != 2):
    print "Invalid Parameters. Please make sure to enter exactly 1 input argument.\n"
    sys.exit()

f = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(f)

flag = 0
packets = []
udppackets = []
icmppackets = []
fragments = []
routers = []
routerips = []
routeruniqueips = []
temp = []
temp2 = []
finaldest = []
winping = []
icmpreply = []
protocols = []
uniqueprotocols = []
count = 1;
ipsrc = "";
ipdst = "";
cnt = 0;
returnflag = 0;

print "--------------------------------------------"
print "Nodal IP Addresses"
print "--------------------------------------------"


#loops through cap file and store data in list
for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)

	cnt += 1

	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		continue

	ip = eth.data
	ipdata = ip.data
	#print str(cnt) + " " + str(type(ipdata))
	#isinstance(,dpkt.udp.UDP)

	#find source port an destination port
	if ip.ttl == 1 and ip.p == 17 and flag == 0 and isinstance(ipdata,dpkt.udp.UDP):
		ipsrc = socket.inet_ntoa(ip.src)
		ipdst = socket.inet_ntoa(ip.dst)
		flag = 1
		print 'IP Address of the Source Node: ' + ipsrc
		print 'IP Address of the Ultimate Destination Node: ' + ipdst + '\n'
		#packets.append([ipsrc, ipdst, ipdata.sport, ipdata.dport, ip.ttl, ip.p])
		protocols.append([ip.p])
		udppackets.append([ipsrc, ipdst, ipdata.sport, ipdata.dport, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
		continue
	elif ip.ttl == 1 and ip.p == 1 and flag == 0 and ipdata.type == 8 and isinstance(ipdata,dpkt.icmp.ICMP):
		ipsrc = socket.inet_ntoa(ip.src)
		ipdst = socket.inet_ntoa(ip.dst)
		flag = 2
		print 'IP Address of the Source Node: ' + ipsrc
		print 'IP Address of the Ultimate Destination Node: ' + ipdst + '\n'
		protocols.append([ip.p])
		#print repr(ipdata.data)
		winping.append([ipsrc, ipdst, ipdata.data.seq, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
		continue
	#else copy all content with src an dest port 
	elif flag == 1 or flag == 2:
	
		if flag == 1:
			#if ip and dst match and UDP packet, append to packet
			if (socket.inet_ntoa(ip.src) == ipsrc or socket.inet_ntoa(ip.src) == ipdst) and (socket.inet_ntoa(ip.dst) == ipsrc or socket.inet_ntoa(ip.dst) == ipdst) and ip.p == 17 and isinstance(ipdata,dpkt.udp.UDP):
				protocols.append([ip.p])
				udppackets.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.sport, ipdata.dport, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
			
			#if ip and dst match and ICMP pacet, append to packet
			elif socket.inet_ntoa(ip.dst) == ipsrc and ip.p == 1:
		
				if ipdata.type == 11:
					protocols.append([ip.p])
					icmppackets.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.data.data.sport, ipdata.data.data.data.dport, ip.ttl, ip.p, ts])
				#print repr(ipdata.data.data.data.sport)
				elif ipdata.type == 3:
					protocols.append([ip.p])
					finaldest.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.data.data.sport, ipdata.data.data.data.dport, ip.ttl, ip.p, ts])
					
			#collects fragments
			if (socket.inet_ntoa(ip.src) == ipsrc or socket.inet_ntoa(ip.src) == ipdst) and (socket.inet_ntoa(ip.dst) == ipsrc or socket.inet_ntoa(ip.dst) == ipdst) and ip.p == 17 and isinstance(ipdata,str):
				fragments.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.id, ip.offset ,ip.ttl, ip.p, ip.len, bool(ip.off & dpkt.ip.IP_MF), ts])
				protocols.append([ip.p])
		elif flag == 2:
			#if ip and dst match and UDP packet, append to packet
			if (socket.inet_ntoa(ip.src) == ipsrc or socket.inet_ntoa(ip.src) == ipdst) and (socket.inet_ntoa(ip.dst) == ipsrc or socket.inet_ntoa(ip.dst) == ipdst) and ip.p == 17 and isinstance(ipdata,dpkt.udp.UDP):
				protocols.append([ip.p])
				udppackets.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.sport, ipdata.dport, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
			
			#if ip and dst match and ICMP pacet, append to packet
			elif ip.p == 1:
				#print ipsrc
				
				if ipdata.type == 11 and socket.inet_ntoa(ip.dst) == ipsrc:
					protocols.append([ip.p])
					icmppackets.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.data.data.data.seq, ip.ttl, ip.p, ts])
				#print repr(ipdata.data.data.data.sport)
				elif ipdata.type == 3:
					protocols.append([ip.p])
					finaldest.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.seq, ip.ttl, ip.p, ts])
				
				if ipdata.type == 8 and socket.inet_ntoa(ip.src) == ipsrc:
					protocols.append([ip.p])
					winping.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.seq, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
					
				if ipdata.type == 0 and socket.inet_ntoa(ip.dst) == ipsrc and socket.inet_ntoa(ip.src) == ipdst:
					protocols.append([ip.p])
					icmpreply.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ipdata.data.seq, ip.ttl, ip.p, bool(ip.off & dpkt.ip.IP_MF), ip.id, ts])
			#collects fragments
			if (socket.inet_ntoa(ip.src) == ipsrc or socket.inet_ntoa(ip.src) == ipdst) and (socket.inet_ntoa(ip.dst) == ipsrc or socket.inet_ntoa(ip.dst) == ipdst) and ip.p == 17 and isinstance(ipdata,str):
				fragments.append([socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.id, ip.offset ,ip.ttl, ip.p, ip.len, bool(ip.off & dpkt.ip.IP_MF), ts])
				protocols.append([ip.p])
			
theCount = 1
lastFlag = 0
#flag = 1
tracker2 = 0
#print udppackets 
#print "\n"
#print winping

#find route ips
while flag == 1:
	for x in range(0,len(udppackets)):
		if udppackets[x][4] == count:
			tracker = 0
			tracker2 = 1
			for y in range(0, len(icmppackets)):
				if udppackets[x][2] == icmppackets[y][2] and udppackets[x][3] == icmppackets[y][3] and tracker == 0:
					routers.append(icmppackets[y])
					routerips.append(icmppackets[y][0])
					tracker = 1
					
	if tracker2 == 0:
		flag = 0
		returnflag = 1
	count += 1
	tracker2 = 0
	#print count

while flag == 2:
	for x in range(0,len(winping)):
		if winping[x][3] == count:
			tracker = 0
			tracker2 = 1
			for y in range(0, len(icmppackets)):
				if winping[x][2] == icmppackets[y][2] and tracker == 0:
					routers.append(icmppackets[y])
					routerips.append(icmppackets[y][0])
					tracker = 1
					
	if tracker2 == 0:
		flag = 0
		returnflag = 2
	count += 1
	tracker2 = 0

#uniquify the list
for x in routerips:
	if x not in routeruniqueips:
		routeruniqueips.append(x)

#print node ips
print 'IP Addresses of Intermediate Destination Nodes:'
for k in range(0, len(routeruniqueips)):
	print '\t' + 'Router ' + str(k+1) + ' ' + routeruniqueips[k]
	


print "\n--------------------------------------------"
print "Protocols"
print "--------------------------------------------"	

#uniquify the list
for x in protocols:
	if x not in uniqueprotocols:
		uniqueprotocols.append(x)

for s in range(0, len(uniqueprotocols)):
	if uniqueprotocols[s][0] == 1:
		print str(uniqueprotocols[s][0]) + ": ICMP"
	elif uniqueprotocols[s][0] == 17:
		print str(uniqueprotocols[s][0]) + ": UDP"

		
print "\n--------------------------------------------"
print "Fragments and Offsets"
print "--------------------------------------------"

offsetlastfragholder = 0

if returnflag == 1:
	for x in range(0, len(udppackets)):

		theCount = 1
		lastFlag = 0
		offsetlastfragholder = 0
	
		#if more frags
		if udppackets[x][6] == 1:
			for p in range(0, len(fragments)):
				if udppackets[x][7] == fragments[p][2] and lastFlag == 0:
					theCount += 1
					if fragments[p][7] == 0:
						offsetlastfragholder = fragments[p][3]
						lastFlag = 1
		if(theCount == 1):
			print("NO FRAGMENT -- Num \'fragments\' from ID #: " + str(udppackets[x][7]) + " is " + str(theCount-1))
		else:
			print("Num fragments from ID #: " + str(udppackets[x][7]) + " is " + str(theCount))
			print("Offset of Last Frag of ID #: " + str(udppackets[x][7]) + " is "  + str(offsetlastfragholder))
elif returnflag == 2:
	for x in range(0, len(winping)):

			theCount = 1
			lastFlag = 0
			offsetlastfragholder = 0
	
			#if more frags
			if winping[x][5] == 1:
				for p in range(0, len(fragments)):
					if winping[x][6] == fragments[p][2] and lastFlag == 0:
						theCount += 1
						if fragments[p][7] == 0:
							offsetlastfragholder = fragments[p][3]
							lastFlag = 1
			if(theCount == 1):
				print("NO FRAGMENT -- Num \'fragments\' from ID #: " + str(winping[x][6]) + " is " + str(theCount-1))
			else:
				print("Num fragments from ID #: " + str(winping[x][6]) + " is " + str(theCount))
				print("Offset of Last Frag of ID #: " + str(winping[x][6]) + " is "  + str(offsetlastfragholder))
		
    
#for k in range(0, len(icmppackets)):
#	print icmppackets[k][3]

tracker2 = 0
temp3 = 0
count = 1


print "\n--------------------------------------------"
print "Intermediate Node RTT and STDs"
print "--------------------------------------------\n"


if returnflag == 1:
	#check for each unique ip
	for p in range(0, len(routeruniqueips)):
		#check for instances of each unique ip
		for y in range(0,len(routers)):
			if routers[y][0] == routeruniqueips[p]:
				#loop through to get timestamps
				for x in range(0,len(udppackets)):
					if udppackets[x][2] == routers[y][2] and udppackets[x][3] == routers[y][3]:
						temp2.append(routers[y][6] - udppackets[x][8])
						if udppackets[x][6] == 1:
							for b in range(0, len(fragments)):
								if udppackets[x][7] == fragments[b][2]:
									temp2.append(routers[y][6] - fragments[b][8])
				
			
						#udppackets[x][8]
	
		avg = sum(temp2)/len(temp2)
		stdev = math.sqrt(sum([(val - avg)**2 for val in temp2])/(len(temp2)))
		#print len(temp2)
		print("RTT from " + ipsrc + " to " + routeruniqueips[p] + " is " + str(avg*100) + " ms")
		print("Standard Deviation is " + str(100*stdev) + " ms" "\n")
		temp2 = []
elif returnflag == 2:
	#check for each unique ip
	for p in range(0, len(routeruniqueips)):
		#check for instances of each unique ip
		for y in range(0,len(routers)):
			if routers[y][0] == routeruniqueips[p]:
				#loop through to get timestamps
				for x in range(0,len(winping)):
					if winping[x][2] == routers[y][2]:
						temp2.append(routers[y][5] - winping[x][7])
						if winping[x][5] == 1:
							for b in range(0, len(fragments)):
								if winping[x][6] == fragments[b][2]:
									temp2.append(routers[y][4] - fragments[b][8])
				
			
						#udppackets[x][8]
	
		avg = sum(temp2)/len(temp2)
		stdev = math.sqrt(sum([(val - avg)**2 for val in temp2])/(len(temp2)))
		#print len(temp2)
		print("RTT from " + ipsrc + " to " + routeruniqueips[p] + " is " + str(avg*100) + " ms")
		print("Standard Deviation is " + str(100*stdev) + " ms" "\n")
		temp2 = []

print "--------------------------------------------"
print "Final Dest RTT and STD"
print "--------------------------------------------\n"

if returnflag == 1:
	for y in range(0,len(finaldest)):
			if finaldest[y][1] == ipsrc:
				#loop through to get timestamps
				for x in range(0,len(udppackets)):
					if udppackets[x][2] == finaldest[y][2] and udppackets[x][3] == finaldest[y][3]:
						temp2.append(finaldest[y][6] - udppackets[x][8])
	avg = sum(temp2)/len(temp2)
	stdev = math.sqrt(sum([(val - avg)**2 for val in temp2])/(len(temp2)))
	
	if len(finaldest) != 0:
		print("RTT from " + ipsrc + " to " + finaldest[0][0] + " is " + str(avg*100) + " ms")
		print("Standard Deviation is " + str(100*stdev) + " ms" "\n")
	else:
		print("No final destination reached")
elif returnflag == 2:
	for y in range(0,len(icmpreply)):
			if icmpreply[y][1] == ipsrc and icmpreply[y][0] == ipdst:
				#loop through to get timestamps
				for x in range(0,len(winping)):
					if winping[x][2] == icmpreply[y][2]:
						temp2.append(icmpreply[y][7] - winping[x][7])
	avg = sum(temp2)/len(temp2)
	stdev = math.sqrt(sum([(val - avg)**2 for val in temp2])/(len(temp2)))
	
	if len(icmpreply) != 0:
		print("RTT from " + ipsrc + " to " + icmpreply[0][0] + " is " + str(avg*100) + " ms")
		print("Standard Deviation is " + str(100*stdev) + " ms" "\n")
	else:
		print("No final destination reached")





