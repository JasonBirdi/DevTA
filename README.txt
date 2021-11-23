INTRODUCTION
------------
This repository is a side project called DevTA (Development Testing Application) used as a testing GUI for displays at a previous company.
DevTA is built completely on Python and utilizes the Kivy library, and is made to run on a Linux machine like it does in the company. DevTA works
as a microcontroller that sends commands to the processor which would control the display on the prototype. The entire processor code cannot be 
added for security of the company given that it is not open-source, but the terminal output displays the byte codes that would have been sent. DevTest.py
is first run and is the heart of the project and corresponds with DevTest.kv to create the UI, and this display has multiple interactive buttons.
These interactive buttons are the commands that control the display that would have changed the screen as the result of a bytecode sent through a pipeline,
but instead I only display the code itself or the command.


REQUIREMENTS
------------
The devices used in my previous company were built on Linux, therefore, the code is setup to run on a Linux OS, I personally run it on a Ubuntu VM.
The Kivy python library may also need to be pip installed to the system for the code to run as it is dependent on these libraries to display the UI.
These requirements are the only INSTALLATIONS required for the project, but that is separate for the repository itself.


CONFIGURATION
------------
In a linux VM, navigate to the DevTA folder, and run:
    python3 DevTest.py
in a terminal. This will automatically open the GUI which can be left using the quit button.


BUGS / ISSUES
-------------
When the python file is run, the terminal output begins to wrap text. This does not change any outputs or the function of the program, but becomes rather
frustrating when trying to clearly view bytecodes and output. Any suggestions to fix this is appreciated.


MAINTAINER / PROGRAMMER
-----------------------
Jason Singh Birdi
Nanotechnology Engineering at University of Waterloo