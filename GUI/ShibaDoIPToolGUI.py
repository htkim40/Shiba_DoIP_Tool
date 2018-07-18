'''
 Author: Hong Kim
'''

import Tkinter as tktr

class ShibaDoIPToolGUI:
	def __init__(self):
		self.width = 900
		self.height = 500
		
		self.rootFigHndl = tktr.Tk()
		self.rootFigHndl.configure(width = self.width, height = self.height, bg = 'black')
		self.SetFigCoords()
		self.rootFigHndl.overrideredirect(True)
		self.rootFigHndl.title("Shiba DoIP Tool")
		self.rootFigHndl.configure(background = 'black')
		
	def SetFigCoords(self):
		# get screen width and height
		ws = self.rootFigHndl.winfo_screenwidth() # width of the screen
		hs = self.rootFigHndl.winfo_screenheight() # height of the screen

		# calculate x and y coordinates for the Tk self.rootFigHndl window
		x = (ws/2) - (self.width/2)
		y = (hs/2) - (self.height/2)

		# set the dimensions of the screen 
		# and where it is placed
		self.rootFigHndl.geometry('%dx%d+%d+%d' % (self.width, self.height, x, y))
	
		
		
def main():
	jupiter = ShibaDoIPToolGUI()
	jupiter.rootFigHndl.mainloop()
		
if __name__ == "__main__":
	main()