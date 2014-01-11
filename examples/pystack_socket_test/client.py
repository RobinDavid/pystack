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
import pystack.pystack_socket as socket


HOST = '192.168.1.37'    # The remote host
#HOST = "www.google.fr"


PORT = 7777              # The same port as used by the server
#PORT = 80
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if s.connect((HOST, PORT)):
    s.sendall('Hello, world\n')
    #s.sendall("GET / HTTP/1.1\r\nHost: www.google.fr\r\nConnection: Close\r\n\r\n")
    #s.sendall("a"*10+"b"*10+"c"*10+"d"*10+"e"*10+"f"*10+"g"*10+"h"*10+"i"*10+"j"*10)
    data = s.recv(1024)
    print('Received '+ repr(data))
    s.close()
else:
    print("Not connected")

import time
time.sleep(4)
s.stop() #To stop stack
