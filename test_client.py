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
import socket

class Client():
    def __init__(self):
        pass
        
    def run(self):
        
        HOST = '192.168.0.21'    # The remote host
        PORT = 7777              # The same port as used by the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        s.sendall('Hello, world\n')
        data = s.recv(1024)
        s.close()
        print('Received'+ repr(data))