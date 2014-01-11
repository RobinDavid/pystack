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
import pystack.pystack_socket #Import the pystack socket module
import sys 
sys.modules["socket_original"] = sys.modules["socket"] #Replace the genuine socket module by ours in sys
sys.modules["socket"] = pystack.pystack_socket
#print sys.modules["socket"]

from test_client import Client #Import a simple client that use socket normally (nothing has been changed inside)
c =Client()
c.run()  #The run launch the client that will use Pystack instead of socket without knowing it



from pystack.pystack import PyStack
s = PyStack() #Retrieve the pystack instance to stop it
s.stop() #Call stop (so that wall rules in iptables will be removed etc ..(just in case))

sys.modules["socket"] = sys.modules["socket_original"] #Put back the original socket in sys (useless because the script ends just after)
sys.modules.pop("socket_original")

#print(sys.modules["socket"])