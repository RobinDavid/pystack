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
from pystack.layers.tcp_application import TCPApplication
from pystack.pystack import PyStack

AF_INET = 2
SOCK_STREAM = 1

class socket(TCPApplication):
    ''' Really basic implementation of socket based on Pystack '''    
    def __init__(self, *args):
        TCPApplication.__init__(self)
        self.stack = PyStack()
        self.stack.register_tcp_application(self)
        self.stack.run(False)
        
    def connect(self, (ip, port)):
        return self.lowerLayers["default"].connect(ip, port)

    def bind(self,(host,port)):
        self.lowerLayers["default"].bind(port,self,True)

    def read(self, nb=None):
        return self.fetch_data(nb)

    def readBlock(self,nb=None):
        while True:
            s = self.read(nb)
            if s != "":
                return s
    
    def recv(self,nb):
        return self.readBlock(nb)
    
    def sendall(self,s):
        self.write(s)
        
    def write(self, data):
        self.send_packet(data)
    
    def close(self):
        return self.lowerLayers["default"].close()
        
    def stop(self):
        self.stack.stop()
        
if __name__ =="__main__":
    
    s = socket()
    '''
    res = s.connect("192.168.1.48", 7777)
    print(res)
    '''
    s.bind(("localhost",8888))
    s.listen(2)
    cli = s.accept()
    
    cli.write("Test")
    
    print("--")
    
    print(cli.readBlock())
    
    cli.close()
    s.close()
    
    s.stop() #Stop stack
