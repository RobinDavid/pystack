#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Author: Robin David
License: GNU GPLv3
Repo: https://github.com/RobinDavid

Copyright (c) 2012 Robin David

PyStack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or 
any later version http://www.gnu.org/licenses/. 
'''
from pystack.pystack import PyStack

stack = PyStack() #Create the stack
stack.run(False) #Run the stack in non-blocking mode

print stack.dns.nslookup("www.google.fr") #Retrieve the dns layer in the stack and use the nslookup method

stack.stop()