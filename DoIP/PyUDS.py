'''
Author: Hong Kim
'''
###UDS DEFINITIONS###

################################################################################
##### DIAGNOSTIC_SESSION_CONTROL_REQUEST(DSC)###################################
################################################################################
DIAGNOSTIC_SESSION_CONTROL_REQUEST = DSC = '10'
################################################################################
# DSC sub-function 0x00 : ISOSAE Reserved ######################################
# <0x10><sub-function> #########################################################
DEFAULT_SESSION = DS = '01'
PROGRAMMING_SESSION = PRGS = '02'
EXTENDED_DIAGNOSTIC_SESSION = EXTDS = '03'
SAFETY_SYSTEM_DIAGNOSTIC_SESSION = SSDS = '04'
#DSC sub-function 0x05-0x3F : ISOSAE Reserved
#DSC sub-function 0x40-0x5F : vehicle manufacturer specifc
#DSC sub-function 0x60-0x7E : system supplier specifc
#DSC sub-function 0x7F : ISOSAE Reserved
################################################################################
# DSC Positive Response Message/Code (PRM/PRC) #################################
# <0x50><sub-function><not supported at Faraday> ###############################
DIAGNOSTIC_SESSION_CONTROL_RESPONSE = DSCPR = '50'


################################################################################
##### ECURESET(ER) #############################################################
################################################################################
ECU_RESET = ER = '11'
################################################################################
# ECU_RESET sub-function 0x00 : ISOSAE Reserved ################################
HARD_RESET = HR = '01'
KEY_OFF_ON_RESET = KOFFONR = '02'
SOFT_RESET = SR = '03'
ENABLE_RAPID_POWER_SHUTDOWN = ERPSD = '04'
DISABLE_RAPID_POWER_SHUTDOWN = DRPSD = '05'
#ECU_RESET sub-function 0x06-0x3F : ISOSAE Reserved
#ECU_RESET sub-function 0x40-0x5F : ISOSAE Reserved
#ECU_RESET sub-function 0x60-0x7E : System Supplier Specific
#ECU_RESET sub-function 0x7F : ISOSAE Reserved
################################################################################
# ER Positive Response Message/Code (PRM/PRC) ##################################
# <0x51><sub-function><power down time -- present on ERPSD> ####################
ECU_RESET_RESPONSE = ERPR = '51'


################################################################################
##### SECURITY ACCESS SERVICE(SA) ##################################################
################################################################################
SECURITY_ACCESS_SERVICE = SA = '27'
# <0x27>,<data record (odd for requestSeed, even for sendKey)>,<optional: security key>
# SECURITY ACCESS SERVICE: REQUEST_SEED : <0x01|0x03|0x05|0x07-0x7D>
# SECURITY ACCESS SERVICE: SEND_KEY: <0x02|0x04|0x06|0x08-0x7F>
################################################################################
# SA Positive Response Message/Code (PRM/PRC) ##################################
SECURITY_ACCESS_RESPONSE = SAPR = '67'


################################################################################
###COMMUNICATION_CONTROL_SERVICE (CC) <0x28><sub-function = [control type]><communication type>
################################################################################
COMMUNICATION_CONTROL_SERVICE = CC = '28'
################################################################################
##CC Sub-functions
ENABLE_RX_TX = ERXTX = '00'
ENABLE_RX_DISABLE_TX = ERXDTX = '01'
DISABLE_RX_ENABLE_TX = DRXETX = '02'
DISABLE_RX_TX = DRXTX = '03'
ENABLE_RX_DISABLE_TX_WITH_ENHANCED_ADDR_INFO = ERXDTXWEAI = '04'
ENABLE_RX_TX_WITH_ENHANCED_ADDR_INFO = ERXTXWEAI = '05'
##CC sub-function 0x06-0x3F : ISOSAE Reserved
##CC sub-function 0x40-0x5F : Vehicle Manufacturer Specific
##CC sub-function 0x60-0x7E : System Supplier Specific 
##CC sub-function 0x7F : ISOSAE Reserved 
################################################################################
###CC communication type bit 0-3 (lower nibble)
###CC communication type bit 0-1 encoding 0x0: ISOSAE Reserved 
NORMAL_COMMUNICATION_MESSAGES = NCM = '01'
NETWORK_MANAGEMENT_COMMUNICATION_MESSAGES = NWMCM = '02'
NETWORK_MANAGEMENT_COMMUNICATION_MESSAGES_NORMAL_COMMUNICATION_MESSAGES = NWMCM_NCM = '03'
################################################################################
###CC communication type bit 2-3 : ISOSAE Reserved -- Keep it 0x0 -- See above that it is kept 0x0
################################################################################
###CC subnet number bit 4-7 (upper nibble) -- Sets the setting for the optional subnet number. 
DISABLE_OR_ENABLE_SPECIFIED_COMMUNICATION_TYPE = DISENSCT = '0'
DISABLE_OR_ENABLE_SPECIFIC_SUBNET_ID_BY_SUBNET_NUMBER = DISENSSIVSN = '1' 
#User should reset as needed. The above is defaulted to 1
DISABLE_OR_ENABLE_NETWORK_WHICH_REQUEST_IS_RECEIVED_ON_NODE = 'F'
#CC PRM <0x68><sub-function >
COMMUNICATION_CONTROL_RESPONSE = CCPR = '68'


#TESTER PRESENT <0x3E><Sub-function>#
TESTER_PRESENT = TP = '3E'
#Subfunctions 
ZERO_SUB_FUNCTION = ZSUBF = '00'
#0x01-0x7F ISOSAE Reserved 
#PRM <7E><Sub-fucntion>
TESTER_PRESENT_RESPONSE = TPPR ='7E'



#REQUEST_DOWNLOAD0x34. <0x34><data format ID><address and legnth format ID><memory address><memory size>
REQUEST_DOWNLOAD = RD = '34'
DATA_FORMAT_ID = DFI_00 = '00' #00 is default, else vehicle manufacturer specific, no compression, no encryption
ADDRESS_AND_LENGTH_FORMAT_ID = ALFID = '44' #44 ff default. 4 bytes for address, 4 bytes for memory size
##Memory address and memory size length specified by ALFID

#TRANSFER_DATA0x36 <TD (0x34)><Block sequence counter(block index)><data>
TRANSFER_DATA = TD = '36'

#REQUEST_TRANSFER_EXIT (0x37)
REQUEST_TRANSFER_EXIT = RTE = '37'


#READ_DATA_BY_IDENTIFIER0x22##
#DIDS: 0x00-0xFF
#USE: 0x22<DID1>..<DIDn>
READ_DATA_BY_IDENTIFIER = RDBI = '22'




#WRITE_DATA_BY_IDENTIFIER0x2E##
#DIDS: 0x00-0xFF
#USE:0x22<DID><DataRecord>
WRITE_DATA_BY_IDENTIFIER = WDBI = '2E'



### Routine Control 0x31 ####
ROUTINE_CONTROL = RC = '31'
START_ROUTINE = STR = '01'
STOP_ROUTINE = STPR = '02'
REQUEST_ROUTINE_RESULTS = RRR = '03'
#all else isosae reserved

#FF Supported Routines 
ERASE_MEMORY = RC_EM = 'FF00'
CHECK_MEMORY = RC_CM = '0202'
CHECK_PROGRAMMING_DEPENDENCIES = RC_CPD = 'FF01' # might be deprecated
REQUEST_COMPONENT_HASH_VALUE = RC_RCHV = 'FF02' #might be deprecated
APPLICATION_AUTHORIZATION = RC_AA = 'FF03'




#NEGATIVE RESPONSE MESSAGE/CODE (NRM/NRC)
SUB_FUNCTION_NOT_SUPPORT = SFNS = '12'
INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = IMLOIF = '13'
CONDITIONS_NOT_CORRECT = CNC = '22'
REQUEST_SEQUENCE_ERROR = RSE = '24'
REQUEST_OUT_OF_RANGE = ROOR = '31'
SECURITY_ACCESS_DENIED = SAD = '33'
INVALID_KEY = IK = '35'
EXCEEDED_NUMBER_OF_ATTEMPS = ENOA = '36'
REQUIRED_TIME_DELAY_NOT_EXPIRED = RTDNE = '37'
GENERAL_PROGRAMMING_FAILURE = GPF = '72'


MEMORY_OPERATION_PENDING = MOPNDNG = '7F3178'
TRANSFER_OPERATION_PENDING = TOPNDNG = '7F3678'



#COMMON DIDs
DID_PROGRAMMING_ATTEMPT_COUNTER = DID_PATTCTR = 'F110'
DID_WRITE_FINGERPRINT 			= DID_WRFPRNT = 'F15A'
DID_READ_FINGERPRINT			= DID_REFPRNT = 'F15B'
DID_BOOT_SW_ID					= DID_BOOTSID = 'F180'
DID_APP_CAL_SW_ID				= DID_APCASID = 'F181'
DID_ACTIVE_DIAGNOSTIC_SESSION	= DID_ADIASES = 'F186'
DID_ECU_SW_NUMBER				= DID_ECUSWNO = 'F188'
DID_VIN_ID						= DID_VINIDNO = 'F190'	