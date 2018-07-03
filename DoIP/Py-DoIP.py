import socket 
import sys

def DoIP_Pack():
    print "DoIP Pack"

class DoIP_Client:
    def __init__(self,IPv4Addr = '0',cPort = 0):
        #init tcp socket
        self.IPAddr = IPv4Addr 
        self.port = cPort
        self.isTCPConnected = 0
        self.isRoutingConnected = 0
        try:
            self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.TCP_Socket.bind((self.IPAddr,self.port))
            print "Socket successfullys created"
        except socket.error as err:
            print "socket creation failed with error %s" %(err)
            
    def __enter__(self):
        return self
    
    def ConnectToDoIPServer(self, IPv4Addr = '162.26.200.101', sPort = 13400, targetECUAddr = 2004):
        print "Connecting to DoIP Server"
        
        
    def RequestRoutingActivation(self):
        print "do nothing"
        
    def __exit__(self, exc_type, exc_value, traceback):
        print "Closing DoIP Client"
        self.TCP_Socket.close()
        
        
if __name__ == '__main__':
    print "main"
    with DoIP_Client() as iHub:
        print iHub.IPAddr
        iHub.ConnectToDoIPServer()