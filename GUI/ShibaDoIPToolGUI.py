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
		self.pushButton1 = QtGui.QPushButton("Start")
		self.pushButton2 = QtGui.QPushButton("Settings")
		self.pushButton3 = QtGui.QPushButton("Stop")
		self.layout.addWidget(self.pushButton1)
		self.layout.addWidget(self.pushButton2)
		self.layout.addWidget(self.pushButton3)
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