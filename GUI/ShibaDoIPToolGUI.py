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
		playBut = QtGui.QPushButton("Play")
		stopBut = QtGui.QPushButton("Stop")
		creatCustomMsgBut = QtGui.QPushButton("Create Custom Message")
		saveSequenceBut = QtGui.QPushButton("Save Sequence")
		clearSequenceBut = QtGui.QPushButton("Clear Sequence")
		saveTerminalBut = QtGui.QPushButton("Save Terminal")
		clearTerminalBut = QtGui.QPushButton("Clear Terminal")
		
		#groupbox for sequence selection. This will eventually have the option
		#to create your own custom message. Need to create a pop up to set 
		#value of message, including an expected response
		self.sequenceSelectionGroupbox = QtGui.QGroupBox()
		self.sequenceSelectionGroupbox.setContentsMargins(10, 10, 10, 10)
		self.sequenceSelectionGroupbox.layout = QtGui.QVBoxLayout()
		self.sequenceSelectionGroupbox.layout.addWidget(creatCustomMsgBut)
		self.sequenceSelectionGroupbox.setLayout(self.sequenceSelectionGroupbox.layout)
		
		self.sequenceEditorGroupbox = QtGui.QGroupBox()
		self.sequenceEditorGroupbox.setContentsMargins(10, 10, 10, 10)
		self.sequenceEditorGroupbox.layout = QtGui.QVBoxLayout()
		self.sequenceEditorGroupbox.layout.addWidget(saveSequenceBut)
		self.sequenceEditorGroupbox.layout.addWidget(clearSequenceBut)
		self.sequenceEditorGroupbox.layout.addWidget(playBut)
		self.sequenceEditorGroupbox.layout.addWidget(stopBut)
		self.sequenceEditorGroupbox.setLayout(self.sequenceEditorGroupbox.layout)
		
		self.targetIPLineEdit  = QtGui.QLineEdit()
		
		self.layout.addWidget(saveTerminalBut)
		self.layout.addWidget(saveTerminalBut)
		
		self.layout.addWidget(self.targetIPLineEdit)
		
		self.layout.addWidget(self.sequenceSelectionGroupbox)
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