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


HOST = '192.168.0.21'    # The remote host
#HOST = "www.google.fr"


PORT = 7777              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#if s.connect((HOST, PORT)):

#s.sendall('Hello, world\n')
#s.sendall("GET / HTTP/1.1\r\nHost: www.google.fr\r\nConnection: Close\r\n\r\n")
#s.sendall("a"*3000)
#-----
s.sendto("Hello sir !", (HOST,PORT))

print s.recvfrom(1024)
print s.recv(1024)
    
s.close()

s.stop() #To stop stack