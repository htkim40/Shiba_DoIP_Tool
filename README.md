Shiba_DoIP_Tool is a tool used to send diagnostic messages over TCPIP (DoIP). 
It is meant to be cross platform across windows, linux, and mac. In its current state, 
major functionality sits in PyDoIP.py in the DoIP directory, and is operated over command line, but will
in the future be supported by a GUI as well. 

To flash an ECU, start by changing your machine's IP address to static 172.26.200.15. 
Drag a hex file into the DoIP directory, and call "python PyDoIP.py flash <hex file.hex> <component ID, 0 = bootloader, 1 = calibration, 2 = application>
Flashing offers a number of different options including downloading via multiple downloads, as well as choosing different IP addresses to target. 

dependencies: 
progressbar -- pip install progressbar
intelhex -- pip install intelhex