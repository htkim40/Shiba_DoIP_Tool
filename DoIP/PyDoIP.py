import socket 
import sys
import binascii
import PyUDS
import time

##DoIP Header Structure : <protocol version><inverse protocol version><payload type><payloadlength><payload>
##Payload format : <local ecu address> <optional: target ecu addres> <optional message ><ASRBISO><ASRBOEM>

PROTOCOL_VERSION = 							'02'
INVERSE_PROTOCOL_VERSION = 					'FD'

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
DOIP_DIAGNOSTIC_MESSAGE = 					'8001'
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

def DoIP_Pack():
    print "DoIP Pack"

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

		try:
			self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.TCP_Socket.bind((self.localIPAddr,self.localPort))
			print "Socket successfully created: Binded to %s:%d" %(self.TCP_Socket.getsockname()[0], self.TCP_Socket.getsockname()[1])
			return 0
		except socket.error as err:
			print "Socket creation failed with error %s" %(err)
			self.TCP_Socket = None
			return err
			
	def __enter__(self):
		return self
				
	def ConnectToDoIPServer(self, address = '172.26.200.101', port = 13400,  routingActivation = True, targetECUAddr = '2004'):
		if self.isTCPConnected:
			print "Error :: Already connected to a server. Close the connection before starting a new one\n"
		else:
			if not self.TCP_Socket:
				print "Warning :: Socket was recently closed but no new socket was created.\nCreating new socket with last available IP address and Port"
				try:
					self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
				print "Requesting routing activation"
				print "TCP SEND ::"
				activationMessage = DoIPMsg(activationString)
				self.TCP_Socket.send(activationString.decode("hex"))
				activationResponse = (binascii.hexlify(self.TCP_Socket.recv(2048))).upper()
				print "TCP RECV ::"
				DoIPResponse = DoIPMsg(activationResponse)
				if DoIPResponse.payload == '10':
					self.isRoutingActivated = True;
					self.targetECUAddr = DoIPResponse.targetAddress
					print "Routing activated with ECU:%s\n" %(self.targetECUAddr)
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
				print "TCP SEND ::"
				DoIPTransmit = DoIPMsg(UDSString)
				self.TCP_Socket.send(UDSString.decode("hex"))
				return 0
			except socket.error as err:
				print "Unable to send UDS Message to ECU:%d. Socket failed with error %s" % (ECUID, err)	
				return -1
				
	def DoIPUDSRecv(self):	
		if self.isTCPConnected:
			try:
				print "TCP RECV ::"
				DoIPResponse = DoIPMsg((binascii.hexlify(self.TCP_Socket.recv(2048))).upper())
				time.sleep(.05) # wait for ACK to be sent

				if DoIPResponse.payloadType == DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE:
					DoIPResponse = self.DoIPUDSRecv()
					return DoIPResponse
				else:
					return -2
			except socket.error as err:
				print "Unable to receive UDS message. Socket failed with error %s" %(err)
				return -1
	def	Terminate(self):
		print "Closing DoIP Client ..."
		self.TCP_Socket.close()
		print "Good bye"
	
	def __exit__(self, exc_type, exc_value, traceback):
		self.Terminate
     
class DoIPMsg: 
	def __init__(self,message = None):
		if not message:
			self.messageString = None
			self.protcolVersion = self.inverseProtocolVersion = None
			self.payloadType = self.payloadLength = None
			self.sourceAddress = self.targetAddress = None
			self.isUDS = False
		else:		
			print str(message)
			self.messageString = message
			self.protcolVersion =  message[0:2]
			self.inverseProtocolVersion = message[2:4]
			self.payloadType = message[4:8]
			self.payloadLength = message[8:16]
			self.sourceAddress = message[16:20]
			if self.DecodePayloadType(self.payloadType) == "Routing activation request":
				self.targetAddress = None
			else:
				self.targetAddress = message[20:24]
			
			if self.DecodePayloadType(self.payloadType) == "Diagnostic message":
				self.isUDS = True
				self.payload = message[24:len(message)]
			else:
				self.payload = message[24:len(message)-len(ASRBISO)]
				self.isUDS = False
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
			
def DoIP_Flash_Hex():
	
	#start a DoIP client
	flashingClient = DoIP_Client()
	
	if flashingClient == 0:
		
		print "Switching to programming diagnostic session" 
		iHub.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)
		
		if iHub.DoIPUDSRecv() != -1 and iHub.DoIPUDSRecv() != -2: #if no negative acknowledge or socket error 
			iHub.DisconnectFromDoIPServer()
			iHub.DisconnectFromDoIPServer()
			time.sleep(1)
			iHub.ConnectToDoIPServer()
			
			#initial seed key exchange 
			
		else:
			print "Error while switching to programming diagnostic session. Exiting flash sequence"
	else : 
		print "Error while creating flash client. Unable to initiate flash sequence"

        
if __name__ == '__main__':
	iHub = DoIP_Client()
	iHub.ConnectToDoIPServer()
	iHub.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS) # change diagnostic sessions to programming session
	iHub.DoIPUDSRecv()
	iHub.DisconnectFromDoIPServer()
	time.sleep(1)
	iHub.ConnectToDoIPServer()
	iHub.DoIPUDSSend('2EF195'+\
		'00'+'0102030405060708'+\
		'01'+'0102030405060708'+\
		'02'+'0102030405060708'+\
		'03'+'0102030405060708'+\
		'04'+'0102030405060708')
	iHub.DoIPUDSRecv()
	iHub.DisconnectFromDoIPServer()