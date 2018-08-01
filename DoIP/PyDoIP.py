import socket 
import sys
import binascii
import PyUDS
import time
import sys

##DoIP Header Structure : <protocol version><inverse protocol version><payload type><payloadlength><payload>
##Payload format : <local ecu address> <optional: target ecu addres> <optional message ><ASRBISO><ASRBOEM>

PROTOCOL_VERSION = DOIP_PV =					'02'
INVERSE_PROTOCOL_VERSION = DOIP_IPV = 			'FD'

##Payload type definitions##
DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE = DOIP_NARP = '0000'
DOIP_VEHICLE_ID_REQUEST = 					'0001'
DOIP_VEHICLE_ID_REQUEST_W_EID = 			'0002'
DOIP_VEHICLE_ID_REQUEST_W_VIN = 			'0003'
DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE = 	'0004'
##DOIP_ROUTING_ACTIVATION_REQUEST : <0005><sourceaddress><activation type><00000000>
DOIP_ROUTING_ACTIVATION_REQUEST = DOIP_RAR = '0005'
##Activation Type
DEFAULT_ACTIVATION = 						'00'
WWH_OBD_ACTIVATION = 						'01'
##0x02-0xDF ISOSAE Reserved
CENTRAL_SECURITY_ACTIVATION = 				'E0'
##0xE1-0xFF OEM Specific 
ACTIVATION_SPACE_RESERVED_BY_ISO = 	ASRBISO = '00000000'
#the code above is mandatory but has no use at the moment. ISOSAE Reserved	
ACTIVATION_SPACE_RESERVED_BY_OEM = 	ASRBOEM = 'ffffffff'		


DOIP_ROUTING_ACTIVATION_RESPONSE = 			'0006'
DOIP_ALIVE_CHECK_REQUEST = 					'0007'
DOIP_ALIVE_CHECK_RESPONSE = 				'0008'
#0x009-0x4000: Reserved by ISO13400
DOIP_ENTITY_STATUS_REQUEST = 				'4001'
DOIP_ENTITY_STATUS_RESPONSE = 				'4002'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST = 	'4003'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE = 	'4004'
#0x4005-0x8000 Reserved by ISO13400
DOIP_DIAGNOSTIC_MESSAGE = DOIP_UDS = 		'8001'
DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE = 		'8002'
DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE = 		'8003'
#0x8004-0xEFFF Reserved by ISO13400
#0xF000-0xFFFF Reserved for manufacturer-specific use


payloadTypeDescription = {
	int(DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE):		 	"Generic negative response",
	int(DOIP_VEHICLE_ID_REQUEST):					"Vehicle ID request",
	int(DOIP_VEHICLE_ID_REQUEST_W_EID):				"Vehicle ID request with EID",	
	int(DOIP_VEHICLE_ID_REQUEST_W_VIN):				"Vehicle ID request with VIN",
	int(DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE):		"Vehicle announcement ID response",
	int(DOIP_ROUTING_ACTIVATION_REQUEST):			"Routing activation request",
	int(DOIP_ROUTING_ACTIVATION_RESPONSE):			"Routing activation response",
	int(DOIP_ALIVE_CHECK_REQUEST):					"Alive check request",
	int(DOIP_ALIVE_CHECK_RESPONSE):					"Alive check response",
	int(DOIP_ENTITY_STATUS_REQUEST):				"Entity status request",
	int(DOIP_ENTITY_STATUS_RESPONSE):				"Entity status response",
	int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST):	"Diagnostic power mode info request",
	int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE): 	"Power mode info response",
	int(DOIP_DIAGNOSTIC_MESSAGE):					"Diagnostic message",
	int(DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE):		"Diagnostic positive acknowledge",
	int(DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE):		"Diagnostic negative acknowledge",		
}
			

defaultTargetIPAddr = '172.26.200.101'
defaultTargetECUAddr = '2004'
			

class DoIP_Client:
	def __init__(self,address = '172.26.200.15',port = 0, ECUAddr = '1111'):
		#init tcp socket
		self.localIPAddr = address 
		self.localPort = port
		self.localECUAddr = ECUAddr
		self.targetIPAddr = None
		self.targetPort = None
		self.targetECUAddr = None
		self.isTCPConnected = False
		self.isRoutingActivated = False
		self.isVerbose = False
		self.TxDoIPMsg = DoIPMsg();
		self.RxDoIPMsg = DoIPMsg();

		try:
			self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			#self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
			self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)#immediately send to wire wout delay
			self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#allows different sockets to reuse ipaddress 

			self.TCP_Socket.settimeout(5.0)
			#self.TCP_Socket.setblocking(1)
			self.TCP_Socket.bind((self.localIPAddr,self.localPort))
			print "Socket successfully created: Binded to %s:%d" %(self.TCP_Socket.getsockname()[0], self.TCP_Socket.getsockname()[1])
			return None
		except socket.error as err:
			print "Socket creation failed with error %s" %(err)
			self.TCP_Socket = None
			return err
			
	def __enter__(self):
		return self
				
	def ConnectToDoIPServer(self, address = defaultTargetIPAddr, port = 13400,  routingActivation = True, targetECUAddr = defaultTargetECUAddr):
		if self.isTCPConnected:
			print "Error :: Already connected to a server. Close the connection before starting a new one\n"
		else:
			if not self.TCP_Socket:
				print "Warning :: Socket was recently closed but no new socket was created.\nCreating new socket with last available IP address and Port"
				try:
					self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					#self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
					self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)#immediately send to wire wout delay
					self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
					self.TCP_Socket.settimeout(5.0)
					#self.TCP_Socket.setblocking(1)
					self.TCP_Socket.bind((self.localIPAddr,self.localPort))
					print "Socket successfully created: Binded to %s:%d\n" %(self.TCP_Socket.getsockname()[0], self.TCP_Socket.getsockname()[1])
				except socket.error as err:
					print "Socket creation failed with error %s" %(err)
					return err
			try:
				print "Connecting to DoIP Server at %s:%d ... " %(address,port)
				self.targetIPAddr = address
				self.targetPort = port
				self.TCP_Socket.connect((address, port)) 
				self.isTCPConnected = True	
				print "Connection to DoIP established\n"
			except socket.error as err: 
				print "Unable to connect to socket at %s:%d. Socket failed with error %s" % (address, port, err)
				self.targetIPAddr = None
				self.targetPort = None
				self.isTCPConnected = False
			
		if routingActivation and self.isTCPConnected: 
			self.targetECUAddr = targetECUAddr
			self.RequestRoutingActivation()
		elif routingActivation and not self.isTCPConnected:
			print "Error :: DoIP client is not connected to a server"
			
	def DisconnectFromDoIPServer(self):
		if self.isTCPConnected:
			try: 
				print "Disconnecting from DoIP server.."
				self.TCP_Socket.shutdown(socket.SHUT_RDWR)
				self.TCP_Socket.close()
				self.TCP_Socket = None
				self.isTCPConnected = 0
				print "Connection successfully shut down\n"
			except socket.error as err:
				print "Unable to disconnect from socket at %s:%d. Socket failed with error %s." %(self.targetIPAddr, self.targetPort, err)
				print "Warning :: Socket is currently in a metastable state." 
			finally:
				self.targetIPAddr = None
				self.targetPort = None
				self.isTCPConnected = 0
		else:
			print "Error :: DoIP client is not connected to a server"
	
	def RequestRoutingActivation(self, activationType = DEFAULT_ACTIVATION, localECUAddr = None, targetECUAddr = None):
		if self.isTCPConnected:
			try: 
				if not localECUAddr:
					localECUAddr = self.localECUAddr
				if not targetECUAddr:
					targetECUAddr = self.targetECUAddr
				DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_ROUTING_ACTIVATION_REQUEST
				payload = localECUAddr + activationType + ASRBISO + ASRBOEM
				payloadLength = "%.8X" % (len(payload)/2) ##divide by 2 because 2 nibbles per byte
				activationString = DoIPHeader + payloadLength + payload		
				self.TxDoIPMsg.UpdateMsg(activationString,self.isVerbose)
				print "Requesting routing activation"
				if self.isVerbose:
					print "TCP SEND ::"
					self.TxDoIPMsg.PrintMessage()
				self.TCP_Socket.send(activationString.decode("hex"))
				activationResponse = (binascii.hexlify(self.TCP_Socket.recv(2048))).upper()
				if self.isVerbose:
					print "TCP RECV ::"
				DoIPResponse = DoIPMsg(activationResponse,self.isVerbose)
				if DoIPResponse.payload == '10':
					self.isRoutingActivated = True;
					self.targetECUAddr = DoIPResponse.targetAddress
					print "Routing activated with ECU: %s\n" %(self.targetECUAddr)
				else:
					self.isRoutingActivated = False;
					print "Unable to activate routing"
			except socket.error as err:
				print "Unable to activate routing with ECU:%d. Socket failed with error %s" % (ECUID, err)
				self.isRoutingActivated = 0;
				self.targetECUAddr = None
		else:
			print "Unable to request routing activation. Currently not connected to a DoIP server"	 
			
	def DoIPUDSSend(self,message, localECUAddr = None, targetECUAddr = None):
		if self.isTCPConnected: 
			try:
				if not localECUAddr:
					localECUAddr = self.localECUAddr
				if not targetECUAddr:
					targetECUAddr = self.targetECUAddr
				DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_DIAGNOSTIC_MESSAGE
				payload = self.localECUAddr + self.targetECUAddr + message #no ASRBISO
				payloadLength = "%.8X" % (len(payload)/2)
				UDSString = DoIPHeader + payloadLength + payload
				self.TxDoIPMsg.UpdateMsg(UDSString)
				if self.isVerbose:
					print "TCP SEND ::"
					self.TxDoIPMsg.PrintMessage()
				self.TCP_Socket.send(UDSString.decode("hex"))
				return 0
			except socket.error as err:
				print "Unable to send UDS Message to ECU:%d. Socket failed with error %s" % (ECUID, err)	
				return -1
				
	def DoIPUDSRecv(self,rxBufLen = 256):	
		if self.isTCPConnected:
			try:
				if self.isVerbose:
					print "TCP RECV ::"
				self.RxDoIPMsg.UpdateMsg(binascii.hexlify(self.TCP_Socket.recv(rxBufLen)).upper(),self.isVerbose)

				#check for positive ack, memory operation pending, or transfer operation pending
				if self.RxDoIPMsg.payloadType == DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE or\
				self.RxDoIPMsg.payload == PyUDS.MOPNDNG or\
				self.RxDoIPMsg.payload == PyUDS.TOPNDNG:
					self.DoIPUDSRecv()
				return self.RxDoIPMsg
			except socket.error as err:
				print "Unable to receive UDS message. Socket failed with error %s" %(err)
				return -1
				
	def DoIPReadDID(self,DID):
		self.DoIPUDSSend(PyUDS.RDBI+DID)
		
		
	def DoIPWriteDID(self,DID,msg):
		self.DoIPUDSSend(PyUDS.WDBI+DID+msg)

	def DoIPEraseMemory(self, componentID):
		if type(componentID) == 'int':	
			componentID = '%.2X'%(0xFF&componentID)		
		print "Erasing memory for component ID: %s...\n" % componentID 
		self.DoIPUDSSend(PyUDS.RC+PyUDS.STR+PyUDS.RC_EM+str(componentID))#### TO DO: CHANGE VALUE TO VARAIBLE
		
	def DoIPCheckMemory(self,componentID,CRCLen = '00', CRC = '00'):
		print "Checking memory...\n"
		if type(componentID) == 'int':
			componentID = '%.2X'%(0xFF&componentID)
		self.DoIPUDSSend(PyUDS.RC+PyUDS.STR+PyUDS.RC_CM+str(componentID)+CRCLen+CRC)
		
	def DoIPRequestDownload(self,memAddr,memSize,dataFormatID = PyUDS.DFI_00,addrLenFormatID = PyUDS.ALFID):
		print "Requesting download data...\n"
		self.DoIPUDSSend(PyUDS.RD+dataFormatID+addrLenFormatID+memAddr+memSize)
		self.DoIPUDSRecv()
		dlLenFormatID = int(self.RxDoIPMsg.payload[2],16)#number of bytes 
		return int(self.RxDoIPMsg.payload[4:(2*dlLenFormatID+4)],16)
		
	def DoIPTransferData(self,blockIndex,data):
		self.DoIPUDSSend(PyUDS.TD + blockIndex + data)
		
	def DoIPRequestTransferExit(self):
		print "Requesting transfer exit..."
		self.DoIPUDSSend(PyUDS.RTE)
	
	def SetVerbosity(self, verbose):
		self.isVerbose = verbose
	
	def	Terminate(self):
		print "Closing DoIP Client ..."
		self.TCP_Socket.close()
		print "Good bye"
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.Terminate
     
class DoIPMsg: 
	def __init__(self,message = None, verbose = False):
		self.UpdateMsg(message,verbose)

	def UpdateMsg(self,message = None, verbose = False):
		if not message:
			self.messageString = None
			self.protcolVersion = self.inverseProtocolVersion = None
			self.payloadType = self.payloadLength = None
			self.sourceAddress = self.targetAddress = None
			self.payload = None
			self.isUDS = False
		else:		
			self.messageString = message
			self.protcolVersion =  message[0:2]
			self.inverseProtocolVersion = message[2:4]
			self.payloadType = message[4:8]
			self.payloadLength = message[8:16]
			self.sourceAddress = message[16:20]
			if self.payloadType == DOIP_ROUTING_ACTIVATION_REQUEST:
				self.targetAddress = None
			else:
				self.targetAddress = message[20:24]
			
			if self.payloadType == DOIP_DIAGNOSTIC_MESSAGE:
				self.isUDS = True
				self.payload = message[24:len(message)]
			else:
				self.payload = message[24:len(message)-len(ASRBISO)]
				self.isUDS = False
			if verbose:
				print str(message)
				self.PrintMessage()
	def PrintMessage(self):
		print "Protocol Version 		: " + str(self.protcolVersion)
		print "Inv. Protocol Version 		: " + str(self.inverseProtocolVersion)
		print "Payload Type 			: " + str(self.payloadType)
		print "Payload Type Description 	: " + str(self.DecodePayloadType(self.payloadType))
		print "Payload Length 			: " + str(self.payloadLength)
		print "Source Address 			: " + str(self.sourceAddress)
		print "Target Address 			: " + str(self.targetAddress)
		print "Payload 			: " + str(self.payload)
		print ""
		
	def DecodePayloadType(self,payloadType):
		return payloadTypeDescription.get(int(payloadType), "Invalid or unregistered diagnostic payload type")
			
def DoIP_Flash_Hex(componentID, ihexFP, targetIP = '172.26.200.101', verbose = False):
	
	#get necessary dependencies
	import progressbar

	print 'Flashing ' + ihexFP + ' to component ID : ' + componentID + '\n'
	
	#start a DoIP client
	
	flashingClient = DoIP_Client()
	flashingClient.SetVerbosity(verbose)
	
	if flashingClient:
	
		flashingClient.ConnectToDoIPServer()
		print "Switching to programming diagnostic session" 
		flashingClient.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)
		doipResponse = flashingClient.DoIPUDSRecv()
		if doipResponse != -1 and doipResponse != -2: #if no negative acknowledge or socket error 
			flashingClient.DisconnectFromDoIPServer()
			time.sleep(1)
			flashingClient.ConnectToDoIPServer()
			
			##### initial seed key exchange ######
			
			#Read DIDS
			print "Reading old tester finger print"
			flashingClient.DoIPReadDID(PyUDS.DID_REFPRNT)
			flashingClient.DoIPUDSRecv()
			
			print "Writing new tester finger print"
			#we will need to replace the first line with the date
			flashingClient.DoIPWriteDID(PyUDS.DID_WRFPRNT,'180727'+\
                                        '484F4E472D2D4849'+\
                                        '4C2D544553542D54'+\
                                        '45414D0304050607'+\
                                        '08090A0B0C0D0E0F'+\
                                        '0001020304050607'+\
                                        '5858585858585858')
			flashingClient.DoIPUDSRecv()
			
			print "Verifying new tester finger print"
			#compare with the date here
			flashingClient.DoIPReadDID(PyUDS.DID_REFPRNT)
			flashingClient.DoIPUDSRecv()
			
			#read and store old BL SW ID 
			#to-do: decipher and store relevant info
			print "Reading Bootloader SW ID"
			flashingClient.DoIPReadDID(PyUDS.DID_BOOTSID)
			flashingClient.DoIPUDSRecv()
			
			#read and store old APP and CAL SW ID
			##to-do: decipher and store relevant info
			print "Reading Application and Calibration SW ID \n"
			flashingClient.DoIPReadDID(PyUDS.DID_APCASID)
			flashingClient.DoIPUDSRecv()
			
			
			#Erase component memory for target component
			flashingClient.DoIPEraseMemory(componentID);
			flashingClient.DoIPUDSRecv()
			
			
			print "Loading hex file: " + ihexFP
			from intelhex import IntelHex
			ih = IntelHex()
			ih.loadhex(ihexFP)
			
			minAddr = ih.minaddr()
			maxAddr = ih.maxaddr()
			memSize = maxAddr - minAddr
			
			minAddrStr = "%.8X" % minAddr
			maxAddrStr = "%.8X" % maxAddr
			memSizeStr = "%.8X" % memSize
			print "\tStart Address: " + minAddrStr + " (%.10d)" % minAddr
			print "\tEnd Address:   " + maxAddrStr + " (%.10d)" % maxAddr
			print "\tTotal Memory:  " + memSizeStr + " (%.10d)\n" % memSize
			
			#request download here. Set maxBlockByteCount to valu from request download
			maxBlockByteCount = flashingClient.DoIPRequestDownload(minAddrStr,memSizeStr) - 2 #subtract 2 for SID and index
			blockByteCount = 0
			
			#read in data from hex file	
			hexDataStr = ''
			hexDataList = []
			for address in range(minAddr,maxAddr+1):
				#print '%.8X\t%.2X' % (address,ih[address])
				hexDataStr = hexDataStr + '%.2X' % ih[address]
				blockByteCount+=1
				if blockByteCount == maxBlockByteCount:
					hexDataList.append(hexDataStr)
					hexDataStr = ''
					blockByteCount = 0
			hexDataList.append(hexDataStr)
			blockIndex = 1
			
			#turn off verbosity, less you be spammed!
			if flashingClient.isVerbose:
				flashingClient.SetVerbosity(False)

			print "Transfering Data -- Max block size(bytes): %.4X (%d)" % (maxBlockByteCount,maxBlockByteCount)		
			#start download progress bar
			bar = progressbar.ProgressBar(maxval=len(hexDataList), \
				widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
			bar.start()			
			bar.update(blockIndex)
			t_Start = time.time()
			
			#begin transferring data
			for block in hexDataList: 
				blockIndexStr = '%.2X' % (blockIndex&0xFF)
				flashingClient.DoIPTransferData(blockIndexStr,block)
				flashingClient.DoIPUDSRecv()
				bar.update(blockIndex)
				blockIndex+=1

			bar.finish()
			t_Finish = time.time()
			t_Download = int(t_Finish-t_Start)
			hr = t_Download/3600
			min = t_Download/60 - hr*60
			sec = t_Download - hr*3600 - min*60
			print "Download complete. Elapsed download time: %.0fdhr %.0fmin %.0fdsec" % (hr,min,sec)
			flashingClient.DoIPRequestTransferExit()
			flashingClient.DoIPUDSRecv()
			
			print 'Total Blocks sent: 		%d'% (len(hexDataList))
			print 'Block size(bytes): 		%d'% (len(hexDataList[0])/2)
			print 'Final block size(bytes):	%d'% (len(hexDataList[len(hexDataList)-1])/2)
			print '\n'

			if verbose:
				flashingClient.SetVerbosity(True)
			
			flashingClient.DoIPCheckMemory(componentID)
			flashingClient.DoIPUDSRecv()
			
			#check for pass
			#if pass, then authorize application
			
			print "Switching to default diagnostic session"
			print "Warning :: ECU will reset" 
			flashingClient.DoIPUDSSend(PyUDS.DSC + PyUDS.DS)
			flashingClient.DoIPUDSRecv()
			
			flashingClient.DisconnectFromDoIPServer()
			time.sleep(2)
							
		else:
			print ret
			print "Error while switching to programming diagnostic session. Exiting flash sequence"
	else : 
		print "Error while creating flash client. Unable to initiate flash sequence"

def main():
	argCount = len(sys.argv)
	if argCount > 1:
		#we have action
		if sys.argv[1] == 'flash':
			if argCount == 2:
				PrintHelp()			
			elif argCount == 4: #default to bgw
				hexFP = sys.argv[2]
				compID = '%.2X'%int(sys.argv[3])
				DoIP_Flash_Hex(compID,hexFP,verbose = False)
			elif argCount == 6: #new ip, new ecu add
				hexFP = sys.argv[2]
				compID = '%.2X'%int(sys.argv[3])
				DoIP_Flash_Hex(compID,hexFP,verbose = False)
				defaultTargetIPAddr = sys.argv[4]
				defaultTargetECUAddr = sys.argv[5]
				#print "Flashing ECU with ECU ID: "+sys.argv[5]+' at IP address:'+sys.argv[4]
			else:
				print 'Invalid number of arguments'
				PrintHelp()
		else:
			print 'Invalid argument' 
			PrintHelp()
	else:
		PrintHelp()
	
def PrintHelp():
	print 'Usage for PyDoIP.py: '
	print 'PyDoIP.py flash [hexfile][component ID] {optional : target IP, target ECUAddr}'+ \
		'\n\t-componentID: 0 = Bootloader, 1 = Calibration, 2 = Application'+\
		'\n\tNote: target ECU address should be explicitly'+\
		'\n\tset if target IP address is set.'+\
		'\n\tIf none of the optional arguments are given,'+\
		'\n\tdefault is 172.26.200.101 2004 (BGW)'
		
		
		
if __name__ == '__main__':
	main()
#	DoIP_Flash_Hex('00','BGW_BL_AB.hex',verbose = False)
#	DoIP_Flash_Hex('02','BGW_App_GAMMA_F-00000159.hex',verbose = False)
#	Test use of doIP message
#	udspl = '5001'
#	plLen = '%.8X'%len(udspl)
#	srcAddr = '1111'
#	trgtAddr = '2004'
#	testMsg = DoIPMsg(DOIP_PV+DOIP_IPV+DOIP_UDS+plLen+udspl+srcAddr+trgtAddr+'5001',verbose = True)	
	
	
