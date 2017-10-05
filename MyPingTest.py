import os, sys, time, signal
import socket, struct, select

RTT_Timer=time.time()
ICMP_ECHO=8
ICMP_ECHOREPLY=0
def MyCheckSum(myICMPpacket):
	evenLength=(len(myICMPpacket)/2)*2
	i=0
	theCheckSum=0
	while i < evenLength:
		if sys.byteorder=="little":
			theCheckSum = theCheckSum + (ord(myICMPpacket[i + 1]) * 256 + ord(myICMPpacket[i]))	
		else:
			theCheckSum = theCheckSum + (ord(myICMPpacket[i]) * 256 + ord(myICMPpacket[i+1]))
		i += 2
	if evenLength < len(myICMPpacket):
		theCheckSum=theCheckSum+ord(myICMPpacket[len(myICMPpacket)-1])
	theCheckSum &= 0xffffffff
	highPart=theCheckSum >> 16
	lowPart=theCheckSum & 0xffff
	theCheckSum=highPart+lowPart
	theCheckSum=theCheckSum+(theCheckSum>>16)
	answer=~theCheckSum & 0xffff
	print answer
	answer=socket.htons(answer)
	return answer

def executePing(theDestination, thePort, icmpSeqNum):
	try:
		MySocket=socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.getprotobyname('icmp'))
	except socket.error as e:
		print e
	#MyID=os.getpid() & 0xffff
	MyID=11527
	MySocket.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,30)
	sendTime=sendPing(theDestination, thePort, MySocket, icmpSeqNum, MyID)
	if sendTime:
		receivedTime, iphTTL, iphSrcIP, datasize, icmpHtype=receivePing(3, MySocket, MyID)
		if receivedTime:
			delay=(receivedTime-sendTime)*1000
			FQHDIp=socket.inet_ntoa(struct.pack("!I",iphSrcIP))
			print FQHDIp, delay, iphTTL, datasize, icmpHtype
		else:
			print "no response from remote"
	else:
		print "sent fails"

def sendPing(theDestination, thePort, MySocket, icmpSeqNum, icmpHeaderID):
	try:
		DestiIP=socket.gethostbyname(theDestination)
	except socket.error as e:
		print e
	icmpCheckSum=0
	icmpHeader=struct.pack('!BBHHH',ICMP_ECHO, 0, icmpCheckSum, icmpHeaderID, icmpSeqNum)
	key = ''.join(chr(x) for x in [0x13, 0x01, 0x02, 0x03, 0x08, 0x09])
	wholeData=icmpHeader+key
	icmpCheckSum=MyCheckSum(wholeData)
	icmpHeader=struct.pack('!BBHHH',ICMP_ECHO, 0, icmpCheckSum, icmpHeaderID, icmpSeqNum)
	wholeData=icmpHeader+key
	try:
		MySocket.sendto(wholeData, (DestiIP,thePort))
	except socket.error as e:
		print e
		return None
	sendTime=time.time()
	print "Ping has been sent to %s" % DestiIP
	return sendTime

def receivePing(timeout,MySocket, icmpHeaderID):
	readyList=select.select([MySocket], [], [], timeout)
	if readyList[0] == []:
		return None, 0, 0, 0, 99
	receivedTime=time.time()
	recvPacket, addr=MySocket.recvfrom(2048)
	ipHeader=recvPacket[0:20]
	iphVersion, iphTypeOfSvc, iphLength, iphID, iphFlags, iphTTL, iphProtocol, iphChecksum, iphSrcIP, iphDestIP \
	= struct.unpack("!BBHHHBBHII", ipHeader)
	print "The TTL is %d" % iphTTL
	icmpHeader=recvPacket[20:28]
	icmpHtype, icmpHcode, icmpHchecksum, icmpHID, icmpHseqNum \
	= struct.unpack("!BBHHH", icmpHeader)
	print "icmp type : %d" % icmpHtype
	if icmpHeaderID == icmpHID:
		datasize=len(recvPacket)-28
		return receivedTime, iphTTL, iphSrcIP, datasize, icmpHtype
	else:
		return None, 0, 0, 0, icmpHtype
	
	
if __name__ == '__main__':
	executePing("www.google.com", 33433, 1)	