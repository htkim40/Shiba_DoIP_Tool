'''
 Author: Hong Kim
'''
import sys 
from PyQt4 import QtGui
from PyQt4 import QtCore

class DoIPToolGUI(QtGui.QMainWindow):

	def __init__(self, parent = None):
		super(DoIPToolGUI, self).__init__(parent)
		self.initUI()
		self.setCentralWidget(self.tabs)
		
	def initUI(self):
		#init window
		self.setGeometry(100,100, 800,500)
		self.setWindowTitle('Shiba DoIP Tool')
		#self.setWindowIcon(QtGui.QIcon('<path to app icon here>'))  
		self.layout = QtGui.QVBoxLayout(self)
		
		#init tabs
		self.tabs	= QtGui.QTabWidget()
		self.sequenceStudio = FF_SequenceStudioWidget(self)
		self.tabs.addTab(self.sequenceStudio.tabHndl,"Sequence Studio")
		self.flashCenter = FF_FlashCenterWidget(self)
		self.tabs.addTab(self.flashCenter.tabHndl,"Flash Center")
		self.layout.addWidget(self.tabs)
		
		self.show()
	
	  
class FF_SequenceStudioWidget(QtGui.QWidget):
	def __init__(self,parent):
		super(FF_SequenceStudioWidget, self).__init__(parent)

		# Set layout of sequence studio tab
		self.tabHndl	= QtGui.QWidget()	
		self.layout	= QtGui.QVBoxLayout()
		
		#push buttons 
		playBtn = QtGui.QPushButton("Play")
		stopBtn = QtGui.QPushButton("Stop")
		creatCustomMsgBtn = QtGui.QPushButton("Create Custom Message")
		saveSequenceBtn = QtGui.QPushButton("Save Sequence")
		clearSequenceBtn = QtGui.QPushButton("Clear Sequence")
		saveTerminalBtn = QtGui.QPushButton("Save Terminal")
		clearTerminalBtn = QtGui.QPushButton("Clear Terminal")
		
		#tables
		msgSelectionItem = []
		msgSelectionTable = QtGui.QTableWidget()
		##can use msg slection items and start appending from a list...
		msgSelectionItem.append( QtGui.QTableWidgetItem("0"))
		
		msgSelectionTable.setWindowTitle("Available Messages")
		msgSelectionTable.setRowCount(10)
		msgSelectionTable.setColumnCount(1)
		##set table data
		msgSelectionTable.setItem(0,0, msgSelectionItem[0])

		
		
		#groupbox for message selection. This will eventually have the option
		#to create your own custom message. Need to create a pop up to set 
		#value of message, including an expected response
		self.messageSelectionGroupbox = QtGui.QGroupBox()
		self.messageSelectionGroupbox.setContentsMargins(10, 10, 10, 10)
		self.messageSelectionGroupbox.layout = QtGui.QVBoxLayout()
		self.messageSelectionGroupbox.layout.addWidget(creatCustomMsgBtn)
		self.messageSelectionGroupbox.layout.addWidget(msgSelectionTable)
		self.messageSelectionGroupbox.setLayout(self.messageSelectionGroupbox.layout)
		

 



		
		
		#groupbox for sequence editor. This field will be used to populate 
		#a table of messages to be sent sequentially. The messages should be
		#drag and droppable. If we hit play, it should start sending out on 
		#the terminal for view. Then rx signals should come too. Each message can
		#come with an optional : 1) wait time, 2) expected rx value. 
		#A check box for doing routing activation to be on or off will be provided too. 
		self.sequenceEditorGroupbox = QtGui.QGroupBox()
		self.sequenceEditorGroupbox.setContentsMargins(10, 10, 10, 10)
		self.sequenceEditorGroupbox.layout = QtGui.QVBoxLayout()
		self.sequenceEditorGroupbox.layout.addWidget(saveSequenceBtn)
		self.sequenceEditorGroupbox.layout.addWidget(clearSequenceBtn)
		self.sequenceEditorGroupbox.layout.addWidget(playBtn)
		self.sequenceEditorGroupbox.layout.addWidget(stopBtn)
		self.sequenceEditorGroupbox.setLayout(self.sequenceEditorGroupbox.layout)
		
		self.targetIPLineEdit  = QtGui.QLineEdit()
		
		self.layout.addWidget(saveTerminalBtn)
		self.layout.addWidget(saveTerminalBtn)
		
		self.layout.addWidget(self.targetIPLineEdit)
		
		self.layout.addWidget(self.messageSelectionGroupbox)
		self.layout.addWidget(self.sequenceEditorGroupbox)
		self.tabHndl.setLayout(self.layout)   
		
			

class FF_FlashCenterWidget(QtGui.QWidget):
	def __init__(self,parent):
		super(FF_FlashCenterWidget, self).__init__(parent)

		# Set layout of sequence center tab
		self.tabHndl	= QtGui.QWidget()	
		self.layout	= QtGui.QVBoxLayout()
		self.pushButton1 = QtGui.QPushButton("Start")
		self.pushButton2 = QtGui.QPushButton("Stop")
		self.layout.addWidget(self.pushButton1)
		self.layout.addWidget(self.pushButton2)
		self.tabHndl.setLayout(self.layout)   
		
    
		
def main():
   app = QtGui.QApplication([])
   root = DoIPToolGUI()
   sys.exit(app.exec_())
	
if __name__ == '__main__':
   main()