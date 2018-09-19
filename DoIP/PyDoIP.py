import socket
import sys
import binascii
import PyUDS
import time
# import argparse

# DoIP Header Structure : <protocol version><inverse protocol version><payload type><payloadlength><payload>
# Payload format : <local ecu address> <optional: target ecu addres> <optional message ><ASRBISO><ASRBOEM>

PROTOCOL_VERSION = DOIP_PV = '02'
INVERSE_PROTOCOL_VERSION = DOIP_IPV = 'FD'

# Payload type definitions#
DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE = DOIP_NARP = '0000'
DOIP_VEHICLE_ID_REQUEST = '0001'
DOIP_VEHICLE_ID_REQUEST_W_EID = '0002'
DOIP_VEHICLE_ID_REQUEST_W_VIN = '0003'
DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE = '0004'
# DOIP_ROUTING_ACTIVATION_REQUEST : <0005><sourceaddress><activation type><00000000>
DOIP_ROUTING_ACTIVATION_REQUEST = DOIP_RAR = '0005'
# Activation Type
DEFAULT_ACTIVATION = '00'
WWH_OBD_ACTIVATION = '01'
# 0x02-0xDF ISOSAE Reserved
CENTRAL_SECURITY_ACTIVATION = 'E0'
# 0xE1-0xFF OEM Specific
ACTIVATION_SPACE_RESERVED_BY_ISO = ASRBISO = '00000000'
# the code above is mandatory but has no use at the moment. ISOSAE Reserved
ACTIVATION_SPACE_RESERVED_BY_OEM = ASRBOEM = 'ffffffff'

DOIP_ROUTING_ACTIVATION_RESPONSE = '0006'
DOIP_ALIVE_CHECK_REQUEST = '0007'
DOIP_ALIVE_CHECK_RESPONSE = '0008'
# 0x009-0x4000: Reserved by ISO13400
DOIP_ENTITY_STATUS_REQUEST = '4001'
DOIP_ENTITY_STATUS_RESPONSE = '4002'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST = '4003'
DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE = '4004'
# 0x4005-0x8000 Reserved by ISO13400
DOIP_DIAGNOSTIC_MESSAGE = DOIP_UDS = '8001'
DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE = '8002'
DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE = '8003'
# 0x8004-0xEFFF Reserved by ISO13400
# 0xF000-0xFFFF Reserved for manufacturer-specific use


payloadTypeDescription = {
    int(DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE): "Generic negative response",
    int(DOIP_VEHICLE_ID_REQUEST): "Vehicle ID request",
    int(DOIP_VEHICLE_ID_REQUEST_W_EID): "Vehicle ID request with EID",
    int(DOIP_VEHICLE_ID_REQUEST_W_VIN): "Vehicle ID request with VIN",
    int(DOIP_VEHICLE_ANNOUNCEMENT_ID_RESPONSE): "Vehicle announcement ID response",
    int(DOIP_ROUTING_ACTIVATION_REQUEST): "Routing activation request",
    int(DOIP_ROUTING_ACTIVATION_RESPONSE): "Routing activation response",
    int(DOIP_ALIVE_CHECK_REQUEST): "Alive check request",
    int(DOIP_ALIVE_CHECK_RESPONSE): "Alive check response",
    int(DOIP_ENTITY_STATUS_REQUEST): "Entity status request",
    int(DOIP_ENTITY_STATUS_RESPONSE): "Entity status response",
    int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_REQUEST): "Diagnostic power mode info request",
    int(DOIP_DIAGNOSTIC_POWER_MODE_INFO_RESPONSE): "Power mode info response",
    int(DOIP_DIAGNOSTIC_MESSAGE): "Diagnostic message",
    int(DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE): "Diagnostic positive acknowledge",
    int(DOIP_DIAGNOSTIC_NEGATIVE_ACKNOWLEDGE): "Diagnostic negative acknowledge",
}

# to be changed later as an option in terminal
defaultTargetIPAddr = '172.26.200.101'
defaultTargetECUAddr = '2004'


class DoIP_Client:
    def __init__(self, address='172.26.200.15', port=0, ECUAddr='1111'):

        # to do: need to add underscores for private properties...
        # init tcp socket
        self._localIPAddr = address
        self._localPort = port
        self._localECUAddr = ECUAddr
        self._targetIPAddr = None
        self._targetPort = None
        self._targetECUAddr = None
        self._isTCPConnected = False
        self._isRoutingActivated = False
        self._isVerbose = False
        self._TxDoIPMsg = DoIPMsg()
        self._RxDoIPMsg = DoIPMsg()
        self._logHndl = open('flash.log', 'w+')

        try:
            self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
            self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # immediately send to wire wout delay
            self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                       1)  # allows different sockets to reuse ipaddress

            self.TCP_Socket.settimeout(5.0)
            # self.TCP_Socket.setblocking(1)
            self.TCP_Socket.bind((self._localIPAddr, self._localPort))
            print "Socket successfully created: Binded to %s:%d" % (
                self.TCP_Socket.getsockname()[0], self.TCP_Socket.getsockname()[1])

        except socket.error as err:
            print "Socket creation failed with error: %s" % err
            if '[Errno 10049]' in str(err):
                print "Consider changing your machine's TCP settings so that it has a satic IP of 172.26.200.15"
            self.TCP_Socket = None

    def __enter__(self):
        return self

    def ConnectToDoIPServer(self, address=defaultTargetIPAddr, port=13400, routingActivation=True,
                            targetECUAddr=defaultTargetECUAddr):
        if self._isTCPConnected:
            print "Error :: Already connected to a server. Close the connection before starting a new one\n"
        else:
            if not self.TCP_Socket:
                print "Warning :: Socket was recently closed but no new socket was created.\nCreating new socket with last available IP address and Port"
                try:
                    self.TCP_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, 12, 1)#supposedly, 12 is TCP_QUICKACK option id
                    self.TCP_Socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,
                                               1)  # immediately send to wire wout delay
                    self.TCP_Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.TCP_Socket.settimeout(5.0)
                    # self.TCP_Socket.setblocking(1)
                    self.TCP_Socket.bind((self._localIPAddr, self._localPort))
                    print "Socket successfully created: Binded to %s:%d\n" % (
                        self.TCP_Socket.getsockname()[0], self.TCP_Socket.getsockname()[1])localPort
                except socket.error as err:
                    print "Socket creation failed with error %s" % (err)
                    self.TCP_Socket = None
                    return err
            if self.TCP_Socket != None:
                try:
                    print "Connecting to DoIP Server at %s:%d... " % (address, port)
                    self._targetIPAddr = address
                    self._targetPort = porthttps://github.com/htkim40/Shiba_DoIP_Tool.git
                    self.TCP_Socket.connect((address, port))
                    self._isTCPConnected = True
                    print "Connection to DoIP established\n"
                except socket.error as err:
                    print "Unable to connect to socket at %s:%d. Socket failed with error: %s" % (address, port, err)
                    self._targetIPAddr = None
                    self._targetPort = None
                    self._isTCPConnected = False
            else:
                return -1

        if routingActivation == False:
            return 0
        elif routingActivation == True and self._isTCPConnected:
            self._targetECUAddr = targetECUAddr
            if self.RequestRoutingActivation() == 0:
                return 0
            else:
                return -1
        elif routingActivation and not self._isTCPConnected:
            print "Error :: DoIP client is not connected to a server"
            return -1

    def DisconnectFromDoIPServer(self):
        if self._isTCPConnected:
            try:
                print "Disconnecting from DoIP server..."
                self.TCP_Socket.shutdown(socket.SHUT_RDWR)
                self.TCP_Socket.close()
                self.TCP_Socket = None
                self._isTCPConnected = 0
                print "Connection successfully shut down\n"
            except socket.error as err:
                print "Unable to disconnect from socket at %s:%d. Socket failed with error: %s." % (
                    self._targetIPAddr, self._targetPort, err)
                print "Warning :: Socket is currently in a metastable state."
            finally:
                self._targetIPAddr = None
                self._targetPort = None
                self._isTCPConnected = 0
        else:
            print "Error :: DoIP client is not connected to a server"

    def RequestRoutingActivation(self, activationType=DEFAULT_ACTIVATION, localECUAddr=None, targetECUAddr=None):
        if self._isTCPConnected:
            try:
                if not localECUAddr:
                    localECUAddr = self._localECUAddr
                if not targetECUAddr:
                    targetECUAddr = self._targetECUAddr
                DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_ROUTING_ACTIVATION_REQUEST
                payload = localECUAddr + activationType + ASRBISO + ASRBOEM
                payloadLength = "%.8X" % (len(payload) / 2)  # divide by 2 because 2 nibbles per byte
                activationString = DoIPHeader + payloadLength + payload
                self._TxDoIPMsg.UpdateMsg(activationString, self._isVerbose)
                print "Requesting routing activation..."
                if self._isVerbose:
                    print "TCP SEND ::"
                    self._TxDoIPMsg.PrintMessage()
                self.TCP_Socket.send(activationString.decode("hex"))
                activationResponse = (binascii.hexlify(self.TCP_Socket.recv(2048))).upper()
                if self._isVerbose:
                    print "TCP RECV ::"
                DoIPResponse = DoIPMsg(activationResponse, self._isVerbose)
                if DoIPResponse.payload[0:2] == '10':
                    self._isRoutingActivated = True
                    self._targetECUAddr = DoIPResponse.targetAddress
                    print "Routing activated with ECU: %s\n" % (self._targetECUAddr)
                    return 0
                else:
                    self._isRoutingActivated = False
                    print "Unable to activate routing"
                    return -1
            except socket.error as err:
                print "Unable to activate routing with ECU:%.4X. Socket failed with error: %s" % (
                    int(targetECUAddr), err)
                self._isRoutingActivated = 0
                self._targetECUAddr = None
                return -1
        else:
            print "Unable to request routing activation. Currently not connected to a DoIP server"

    def DoIPUDSSend(self, message, localECUAddr=None, targetECUAddr=None, logging=True):
        if self._isTCPConnected:
            try:
                if not localECUAddr:
                    localECUAddr = self._localECUAddr
                if not targetECUAddr:
                    targetECUAddr = self._targetECUAddr
                DoIPHeader = PROTOCOL_VERSION + INVERSE_PROTOCOL_VERSION + DOIP_DIAGNOSTIC_MESSAGE
                payload = self._localECUAddr + self._targetECUAddr + message  # no ASRBISO
                payloadLength = "%.8X" % (len(payload) / 2)
                UDSString = DoIPHeader + payloadLength + payload
                self._TxDoIPMsg.UpdateMsg(UDSString)
                if logging == True:
                    if self._TxDoIPMsg.isUDS:
                        self._logHndl.write('Client: ' + self._TxDoIPMsg.payload + '\n')
                    else:
                        self._logHndl.write('Client: ' + self._TxDoIPMsg.DecodePayloadType() + '\n')
                if self._isVerbose:
                    print "TCP SEND ::"
                    self._TxDoIPMsg.PrintMessage()
                self.TCP_Socket.send(UDSString.decode("hex"))
                return 0
            except socket.error as err:
                print "Unable to send UDS Message to ECU:%d. Socket failed with error: %s" % (targetECUAddr, err)
                return -1
        else:
            print "Not currently connected to a server"
            return -3

    def DoIPUDSRecv(self, rxBufLen=1024, logging=True):
        if self._isTCPConnected:
            try:
                if self._isVerbose:
                    print "TCP RECV ::"
                self._RxDoIPMsg.UpdateMsg(binascii.hexlify(self.TCP_Socket.recv(rxBufLen)).upper(), self._isVerbose)
                if logging == True:
                    if self._RxDoIPMsg.isUDS:
                        self._logHndl.write('Server: ' + self._RxDoIPMsg.payload + '\n')
                    else:
                        self._logHndl.write('Server: ' + self._RxDoIPMsg.DecodePayloadType() + '\n')
                # check for positive ack, memory operation pending, or transfer operation pending
                if self._RxDoIPMsg.payloadType == DOIP_DIAGNOSTIC_POSITIVE_ACKNOWLEDGE or \
                        self._RxDoIPMsg.payload == PyUDS.MOPNDNG or \
                        self._RxDoIPMsg.payload == PyUDS.TOPNDNG:
                    return self.DoIPUDSRecv()
                elif self._RxDoIPMsg.payloadType == DOIP_GENERIC_NEGATIVE_ACKNOWLEDGE:
                    return -2
                else:
                    return 0
            except socket.error as err:
                print "Unable to receive UDS message. Socket failed with error: %s" % (err)
                return -1
        else:
            print "Not currently connected to a server"
            return -3

    def DoIPReadDID(self, DID):
        self.DoIPUDSSend(PyUDS.RDBI + DID)
        return self.DoIPUDSRecv()

    def DoIPWriteDID(self, DID, msg):
        self.DoIPUDSSend(PyUDS.WDBI + DID + msg)
        return self.DoIPUDSRecv()

    def DoIPRoutineControl(self, subfunction, routine_id, op_data):
        print "Sending routine control command, subfunction:" + str(subfunction) + "routine id:" + str(routine_id)
        self.DoIPUDSSend(PyUDS.RC + subfunction + routine_id + op_data)
        return self.DoIPUDSRecv()

    def DoIPEraseMemory(self, componentID):
        if type(componentID) == 'int':
            componentID = '%.2X' % (0xFF & componentID)
        print "Erasing memory for component ID: %s..." % componentID
        self.DoIPUDSSend(PyUDS.RC + PyUDS.STR + PyUDS.RC_EM + str(componentID))  # #  TO DO: CHANGE VALUE TO VARAIBLE
        return self.DoIPUDSRecv()

    def DoIPCheckMemory(self, componentID, CRCLen='00', CRC='00'):
        print "Checking memory..."
        if type(componentID) == 'int':
            componentID = '%.2X' % (0xFF & componentID)
        self.DoIPUDSSend(PyUDS.RC + PyUDS.STR + PyUDS.RC_CM + str(componentID) + CRCLen + CRC)
        return self.DoIPUDSRecv()

    def DoIPSwitchDiagnosticSession(self, sessionID=1):
        targetSession = ''
        if int(sessionID) == 1:
            print "Switching to Default Diagnostic Session..."
            self.DoIPUDSSend(PyUDS.DSC + PyUDS.DS)
        elif int(sessionID) == 2:
            print "Switching to Programming Diagnostic Session..."
            self.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)
        elif int(sessionID) == 3:
            print "Switching to Extended diagnostic Session..."
            self.DoIPUDSSend(PyUDS.DSC + PyUDS.EXTDS)
        else:
            print "Invalid diagnostic session. Session ID: 1) Default session 2) Programming session 3) Extended session"
            return -1

        return self.DoIPUDSRecv()

    def DoIPRequestDownload(self, memAddr, memSize, dataFormatID=PyUDS.DFI_00, addrLenFormatID=PyUDS.ALFID):
        print "Requesting download data..."
        self.DoIPUDSSend(PyUDS.RD + dataFormatID + addrLenFormatID + memAddr + memSize)
        if (self.DoIPUDSRecv() == 0):
            print "Request download data success\n"
            dlLenFormatID = int(self._RxDoIPMsg.payload[2], 16)  # number of bytes
        else:
            return -1
        return int(self._RxDoIPMsg.payload[4:(2 * dlLenFormatID + 4)], 16)

    def DoIPTransferData(self, blockIndex, data):
        self.DoIPUDSSend(PyUDS.TD + blockIndex + data)
        return self.DoIPUDSRecv()

    def DoIPRequestTransferExit(self):
        print "Requesting transfer exit..."
        self.DoIPUDSSend(PyUDS.RTE)
        return self.DoIPUDSRecv()

    def SetVerbosity(self, verbose):
        self._isVerbose = verbose

    def Terminate(self):
        print "Closing DoIP Client ..."
        self.TCP_Socket.close()
        self._logHndl.close()
        print "Good bye"

    def __exit__(self, exc_type, exc_value, traceback):
        self.Terminate()


class DoIPMsg:
    def __init__(self, message=None, verbose=False):
        self.UpdateMsg(message, verbose)

    def UpdateMsg(self, message=None, verbose=False):
        if not message:
            self.messageString = None
            self.protcolVersion = self.inverseProtocolVersion = None
            self.payloadType = self.payloadLength = None
            self.sourceAddress = self.targetAddress = None
            self.payload = None
            self.isUDS = False
        else:
            self.messageString = message
            self.protcolVersion = message[0:2]
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
                self.payload = message[24:len(message) - len(ASRBISO)]
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

    def DecodePayloadType(self, payloadType=None):
        if payloadType == None:
            payloadType = self.payloadType
        return payloadTypeDescription.get(int(payloadType), "Invalid or unregistered diagnostic payload type")

def DoIP_RoutineControl(subfunction, routine, op, verbose=False):
    t_FlashStart = time.time()

    # start a DoIP client
    DoIPClient = DoIP_Client()
    DoIPClient.SetVerbosity(verbose)

    if DoIPClient.TCP_Socket:
        DoIPClient.ConnectToDoIPServer()

        if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:
            DoIPClient.DoIPRoutineControl(subfunction, routine, op)
            '''
            print "Switching to programming diagnostic session"
            DoIPClient.DoIPUDSSend(PyUDS.DSC + PyUDS.EXTDS)

            if DoIPClient.DoIPUDSRecv() == 0:  # if no negative acknowledge or socket error
                print "Successfully switched to programming diagnostic session\n"
                DoIPClient.DisconnectFromDoIPServer()
                # time.sleep(1)
                DoIPClient.ConnectToDoIPServer()

                if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:
                    pass
                else:
                    downloadErr = True

            else:
                print "Session switch failed."
            '''
        else:
            print "Can not connect to DoIP Server."
    else:
        print "TCP Socket creation failed."

def DoIP_Flash_Hex(componentID, ihexFP, targetIP='172.26.200.101', verbose=False, multiSegment=False):
    # get necessary dependencies
    import progressbar

    t_FlashStart = time.time()

    print '\nFlashing ' + ihexFP + ' to component ID : ' + componentID + '\n'

    # start a DoIP client
    DoIPClient = DoIP_Client()
    DoIPClient.SetVerbosity(verbose)

    if DoIPClient.TCP_Socket:
        downloadErr = False
        DoIPClient.ConnectToDoIPServer()

        if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:

            print "Switching to programming diagnostic session"
            DoIPClient.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)

            if DoIPClient.DoIPUDSRecv() == 0:  # if no negative acknowledge or socket error
                print "Successfully switched to programming diagnostic session\n"
                DoIPClient.DisconnectFromDoIPServer()
                # time.sleep(1)
                DoIPClient.ConnectToDoIPServer()

                if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:

                    # # # initial seed key exchange # # #
                    # to do : implement seed key exchange

                    # read DIDs
                    print "Starting pre-download checks..."
                    print "\tReading old tester finger print"
                    if (DoIPClient.DoIPReadDID(PyUDS.DID_REFPRNT) == 0):
                        print "\tRead success"
                        print "\tWriting new tester finger print"
                        # to do: we will need to replace the first line with the date
                        if DoIPClient.DoIPWriteDID(PyUDS.DID_WRFPRNT, '180727' + \
                                                                      '484F4E472D2D4849' + \
                                                                      '4C2D544553542D54' + \
                                                                      '45414D0304050607' + \
                                                                      '08090A0B0C0D0E0F' + \
                                                                      '0001020304050607' + \
                                                                      '5858585858585858') == 0:
                            print "\tWrite success"
                            print "\tVerifying new tester finger print"

                            # compare with the date here
                            if DoIPClient.DoIPReadDID(PyUDS.DID_REFPRNT) == 0:
                                # read and store old BL SW ID
                                # to-do: decipher and store relevant info
                                print "\tRead success"
                                print "\tReading Bootloader SW ID"
                                if DoIPClient.DoIPReadDID(PyUDS.DID_BOOTSID) == 0:

                                    # read and store old APP and CAL SW ID
                                    # to-do: decipher and store relevant info
                                    print "\tRead success"
                                    print "\tReading Application and Calibration SW ID"
                                    if DoIPClient.DoIPReadDID(PyUDS.DID_APCASID) == 0:
                                        print "\tRead success"
                                        print "Pre-download checks complete\n"

                                        # Erase component memory for target component
                                        if DoIPClient.DoIPEraseMemory(componentID) == 0:
                                            print "Erase memory success\n"
                                        else:
                                            downloadErr = True
                                    else:
                                        downloadErr = True
                                else:
                                    downloadErr = True
                            else:
                                downloadErr = True
                        else:
                            downloadErr = True
                    else:
                        downloadErr = True

                    if not downloadErr:
                        print "Loading hex file: " + ihexFP
                        from intelhex import IntelHex
                        ih = IntelHex()
                        ih.loadhex(ihexFP)

                        if multiSegment:
                            print "Downloading in multiple segments..."
                            segments = ih.segments()
                        else:
                            print "Downloading in a single filled segment..."
                            minAddr = ih.minaddr()
                            maxAddr = ih.maxaddr()
                            segments = [(ih.minaddr(), ih.maxaddr())]

                        for (minAddr, maxAddr) in segments:

                            if multiSegment:
                                maxAddr -= 1

                            memSize = maxAddr - minAddr + 1

                            minAddrStr = "%.8X" % minAddr
                            maxAddrStr = "%.8X" % maxAddr
                            memSizeStr = "%.8X" % memSize
                            print "\tStart Address: " + minAddrStr + " (%.10d)" % minAddr
                            print "\tEnd Address:   " + maxAddrStr + " (%.10d)" % maxAddr
                            print "\tTotal Memory:  " + memSizeStr + " (%.10d)\n" % memSize

                            # request download here. Set maxBlockByteCount to valu from request download
                            maxBlockByteCount = DoIPClient.DoIPRequestDownload(minAddrStr, memSizeStr)
                            if maxBlockByteCount >= 2:
                                maxBlockByteCount -= 2  # subtract 2 for SID and index
                            else:
                                print "Error while requesting download data. Exiting out of flash sequencing"
                                downloadErr = True
                                break

                            blockByteCount = 0
                            hexDataStr = ''
                            hexDataList = []

                            for address in range(minAddr, maxAddr + 1):
                                # print '%.8X\t%.2X' % (address,ih[address])
                                hexDataStr = hexDataStr + '%.2X' % ih[address]
                                blockByteCount += 1
                                if blockByteCount == maxBlockByteCount:
                                    hexDataList.append(hexDataStr)
                                    hexDataStr = ''
                                    blockByteCount = 0
                            hexDataList.append(hexDataStr)
                            blockIndex = 1

                            # turn off verbosity, less you be spammed!
                            if DoIPClient.isVerbose:
                                DoIPClient.SetVerbosity(False)

                            print "Transfering Data -- Max block size(bytes): 0x%.4X (%d)" % (
                                maxBlockByteCount, maxBlockByteCount)

                            # start download progress bar
                            bar = progressbar.ProgressBar(maxval=len(hexDataList),
                                                          widgets=[progressbar.Bar('=', '[', ']'), ' ',
                                                                   progressbar.Percentage()])
                            bar.start()
                            bar.update(blockIndex)

                            t_Start = time.time()

                            # begin transferring data
                            for block in hexDataList:
                                blockIndexStr = '%.2X' % (blockIndex & 0xFF)
                                if DoIPClient.DoIPTransferData(blockIndexStr, block) != 0:
                                    downloadErr = True
                                    break
                                bar.update(blockIndex)
                                blockIndex += 1
                            bar.finish()
                            if not downloadErr:
                                if DoIPClient.DoIPRequestTransferExit() == 0:
                                    t_Finish = time.time()
                                    t_Download = int(t_Finish - t_Start)
                                    hr_Download = t_Download / 3600
                                    min_Download = t_Download / 60 - hr_Download * 60
                                    sec_Download = t_Download - hr_Download * 3600 - min_Download * 60
                                    print "Download complete. Elapsed download time: %.0fdhr %.0fmin %.0fdsec" % (
                                        hr_Download, min_Download, sec_Download)
                                    print 'Total Blocks sent: 		%d' % (len(hexDataList))
                                    print 'Block size(bytes): 		%d' % (len(hexDataList[0]) / 2)
                                    print 'Final block size(bytes):	%d\n' % (
                                            len(hexDataList[len(hexDataList) - 1]) / 2)

                                else:
                                    print "Request transfer exit failure. Exiting out of flash sequence"
                                    downloadErr = True
                                    break
                            else:
                                print "Transfer data failure. Exiting out of flash sequence"
                                downloadErr = True
                                break
                        # reset verbosity
                        if verbose:
                            DoIPClient.SetVerbosity(True)

                        if not downloadErr:
                            # request check memory
                            if DoIPClient.DoIPCheckMemory(componentID) == 0:
                                if DoIPClient.RxDoIPMsg.payload[9] == '0':
                                    print "Check memory passed. Authorizing software update\n"
                                # if pass, then authorize application . to do: application authorization
                                else:
                                    print "Check memory failed. Software update is invalid. Exiting out of update sequence\n"

                                print "Switching to default diagnostic session..."
                                print "\tWarning :: ECU will reset"
                                if DoIPClient.DoIPUDSSend(PyUDS.DSC + PyUDS.DS) == 0:
                                    print "Successfully switched to default diagnostic session\n"
                                    print "Software update success!!\n"

                                    t_FlashEnd = time.time()
                                    t_Flash = int(t_FlashEnd - t_FlashStart)
                                    hr_Flash = t_Flash / 3600
                                    min_Flash = t_Flash / 60 - hr_Flash * 60
                                    sec_Flash = t_Flash - hr_Flash * 3600 - min_Flash * 60
                                    print "-----------------------------------------------------------------------------------"
                                    print "Flash sequence complete. Elapsed flash time: %.0fdhr %.0fmin %.0fdsec \n" % (
                                        hr_Flash, min_Flash, sec_Flash)
                                    print "-----------------------------------------------------------------------------------"

                            else:
                                print "Error while checking memory. Exiting out of flash sequence."
                        else:
                            print "You got so close! But alas, my code is either not very good, or something happened in the release\n"

                        # disconnect from the server gracefully please
                        print "Exiting out of flash sequence...\n"
                        DoIPClient.DisconnectFromDoIPServer()
                        time.sleep(5)

                    else:
                        print "Error while performing pre-programming procedure. Exiting flash sequence."
                else:
                    print "Error while reconnecting to ECU or during routing activation. Exiting flash sequence."
            else:
                print "Error while switching to programming diagnostic session. Exiting flash sequence."
        else:
            print "Error while connect to ECU and//or activate routing. Exiting flash sequence."
    else:
        print "Error while creating flash client. Unable to initiate flash sequence."


def DoIP_Erase_Memory(componentID, targetIP='172.26.200.101', verbose=False, ):
    # Function to erase component ID
    print "Erasing memory from component ID: " + (componentID)
    # start a DoIP client
    DoIPClient = DoIP_Client()
    DoIPClient.SetVerbosity(verbose)

    if DoIPClient.TCP_Socket:
        DoIPClient.ConnectToDoIPServer()

        if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:

            print "Switching to programming diagnostic session"
            DoIPClient.DoIPUDSSend(PyUDS.DSC + PyUDS.PRGS)

            if DoIPClient.DoIPUDSRecv() == 0:  # if no negative acknowledge or socket error
                print "Successfully switched to programming diagnostic session\n"
                DoIPClient.DisconnectFromDoIPServer()
                # time.sleep(1)
                DoIPClient.ConnectToDoIPServer()

                if DoIPClient.isTCPConnected:
                    if DoIPClient.DoIPEraseMemory(componentID) == 0:
                        print "Erase memory success\n"
                    else:
                        print "Error erasing memory. Exiting out of sequence"
                else:
                    print "Error while reconnecting to ECU and//or activate. Exiting erase memory sequence."
            else:
                print "Error while switching to programming diagnostic session. Exiting erase memory sequence."

            DoIPClient.DisconnectFromDoIPServer()
            time.sleep(5)


        else:
            print "Error while connect to ECU and//or activate routing. Exiting erase memory sequence."
    else:
        print "Error while creating DoIP client. Unable to initiate erase memory sequence."


def Test_Switch_Diagnostic_Session(targetIP='172.26.200.101', verbose=False, sessionID=1):
    # Function to Switch Diagnostic Session Then Close Socket
    print "Switching to sessionID: " + str(sessionID)
    # start a DoIP client
    DoIPClient = DoIP_Client()
    DoIPClient.SetVerbosity(verbose)

    if DoIPClient.TCP_Socket:
        DoIPClient.ConnectToDoIPServer()

        if DoIPClient.isTCPConnected and DoIPClient.isRoutingActivated:

            print "Switching diagnostic session"
            print DoIPClient.DoIPSwitchDiagnosticSession(sessionID)

            DoIPClient.DisconnectFromDoIPServer()
            time.sleep(5)


        else:
            print "Error while connect to ECU and//or activate routing. Exiting erase memory sequence."
    else:
        print "Error while creating DoIP client. Unable to initiate erase memory sequence."


def main():
    # Temporary quick way of getting user input. This will be replaced with usage of argparse.
    argCount = len(sys.argv)
    print "System arugments: " + ', '.join(sys.argv)
    if argCount > 1:
        # we have action
        if sys.argv[1] == 'flash':
            if argCount == 2:
                PrintHelp()
            elif argCount == 4:  # default to bgw
                hexFP = sys.argv[2]
                compID = '%.2X' % int(sys.argv[3])
                DoIP_Flash_Hex(compID, hexFP, verbose=False)
            elif argCount == 5:  # default to bgw -- multiple block download
                hexFP = sys.argv[2]
                compID = '%.2X' % int(sys.argv[3])
                DoIP_Flash_Hex(compID, hexFP, verbose=False, multiSegment=True)
            elif argCount == 6:  # new ip, new ecu add
                hexFP = sys.argv[2]
                compID = '%.2X' % int(sys.argv[3])
                DoIP_Flash_Hex(compID, hexFP, verbose=False)
                defaultTargetIPAddr = sys.argv[4]
                defaultTargetECUAddr = sys.argv[5]
            # print "Flashing ECU with ECU ID: "+sys.argv[5]+' at IP address:'+sys.argv[4]
            elif argCount == 7:  # new ip, new ecu add
                hexFP = sys.argv[2]
                compID = '%.2X' % int(sys.argv[3])
                DoIP_Flash_Hex(compID, hexFP, verbose=False, multiSegment=True)
                defaultTargetIPAddr = sys.argv[4]
                defaultTargetECUAddr = sys.argv[5]
            # print "Flashing ECU with ECU ID: "+sys.argv[5]+' at IP address:'+sys.argv[4]

            else:
                print 'Invalid number of arguments'
                PrintHelp()
        elif sys.argv[1] == 'erase':
            if argCount == 2:
                PrintHelp()
            elif argCount == 3:
                if int(sys.argv[2]) == 0 or int(sys.argv[2]) == 1 or int(sys.argv[2]) == 2:
                    compID = '%.2X' % int(sys.argv[2])
                    DoIP_Erase_Memory(compID)
                # erase here
                else:
                    print "Invalid component ID"
            else:
                print 'Invalid number of arguments'
                PrintHelp()

        elif sys.argv[1] == 'routine':
            if argCount < 4:
                PrintHelp()
            elif argCount == 4 or argCount == 5:
                subfunction = sys.argv[2]
                routine = sys.argv[3]
                # argv[4]/op optional
                op = ''
                if argCount == 5:
                    op = sys.argv[4]
                DoIP_RoutineControl(subfunction, routine, op, verbose=True)

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
    print 'PyDoIP.py flash [hexfile][component ID]{optional: target IP, target ECUAddr}' + \
          '\n\nPyDoIP.py flash [hexfile][component ID]{optional: multiSegment}' + \
          '\n\nPyDoIP.py flash [hexfile][component ID]{optional: target IP, target ECUAddr}' + \
          '\n\nPyDoIP.py flash [hexfile][component ID]{optional: target IP, target ECUAddr, multiSegment}' + \
          '\n\n\t:: ComponentID: 0 = Bootloader, 1 = Calibration, 2 = Application' + \
          '\n\t:: IP: XXX.XXX.XXX.XXX, i.e. 172.026.200.101' + \
          '\n\tNote: target ECU address should be explicitly' + \
          '\n\tset if target IP address is set.' + \
          '\n\tIf none of the optional arguments are given,' + \
          '\n\tdefault is 172.26.200.101 2004 (BGW)\n'
    print 'PyDoIP.py erase [component ID]' + \
          '\n\n\t::componentID: 0 = Bootloader, 1 = Calibration, 2 = Application'


if __name__ == '__main__':
    main()
#	Test_Switch_Diagnostic_Session(2)
#	DoIP_Flash_Hex('00','BGW_BL_AB.hex',verbose = False)
#	DoIP_Flash_Hex('02','BGW_App_GAMMA_F-00000159.hex',verbose = False)
#	Test use of doIP message
#	udspl = '5001'
#	plLen = '%.8X'%len(udspl)
#	srcAddr = '1111'
#	trgtAddr = '2004'
#	testMsg = DoIPMsg(DOIP_PV+DOIP_IPV+DOIP_UDS+plLen+udspl+srcAddr+trgtAddr+'5001',verbose = True)
