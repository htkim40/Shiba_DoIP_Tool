import socket 
import sys

def DoIP_Pack():
    print "DoIP Pack"

class DoIP_Client:
    def __init__(self,address = '172.26.200.15',port = 13300, ECUAddr = '1111'):
		#init tcp socket
		self.localIPAddr = address 
		self.localPort = port
		self.localECUAddr = ECUAddr
		self.targetECUAddr = None
		self.isTCPConnected = 0
		self.isRoutingActivated = 0

		try:
			self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.TCP_Socket.bind((self.localIPAddr,self.localPort))
			print "Socket successfullys created"
		except socket.error as err:
			print "Socket creation failed with error %s" %(err)
				
    def ConnectToDoIPServer(self, address = '172.26.200.101', port = 13400,  routingActivation = True, targetECUAddr = '2004'):
		print "Connecting to DoIP Server at %s:%d" %(address,port)
		try:
			self.TCP_Socket.connect((address, port)) 
			self.isTCPConnected = 1	
		except socket.error as err: 
			print "Unable to connect to socket at %s:%d. Socket failed with error %s" % (address, port, err)
			self.isTCPConnected = 0

		if routingActivation: 
			self.RequestRoutingActivation()
        
    def RequestRoutingActivation(self,targetECUaddr = '2004'):
		if self.isTCPConnected:
			try: 
				print "Requesting routing activation"
				############self.TCP_Socket.send()#############
				self.isRoutingActivated = 1;
				self.targetECUAddr = targetECUAddr
			except socket.error as err:
				print "Unable to activate routing with ECU:%d. Socket failed with error %s" % (ECUID, err)
				self.isRoutingActivated = 0;
				self.targetECUAddr = None
		else:
			print "Unable to request routing activation. Currently not connected to a DoIP server"	 
        
    def __exit__(self, exc_type, exc_value, traceback):
        print "Closing DoIP Client"
        self.TCP_Socket.close()
        
        
if __name__ == '__main__':
	print "main"
	iHub = DoIP_Client()
	iHub.ConnectToDoIPServer()
	iHub.TCP_Socket.close()