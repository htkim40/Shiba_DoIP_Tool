'''
 Author: Hong Kim
'''

import Tkinter as tktr

class ShibaDoIPToolGUI:
	def __init__(self):
		self.rootFigHndl = tktr.Tk()
		self.rootFigHndl.overrideredirect(True)
		self.rootFigHndl.title("Shiba DoIP Tool")
		self.rootFigHndl.configure(background = 'black')
		
		
def main():
	jupiter = ShibaDoIPToolGUI()
	jupiter.rootFigHndl.mainloop()
		
if __name__ == "__main__":
	main()