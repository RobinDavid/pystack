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

from pystack.layers.tcp_session import TCPSession
from pystack.layers.tcp_application import TCPApplication
from pystack.pystack import PyStack

def binvalue(val, bitsize): #Return the binary value as a string of the given size 
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    return binval.zfill(bitsize)

def nsplit(s, n):#Split a list into sublists of size "n"
    return [s[k:k+n] for k in xrange(0, len(s), n)]

def int_to_string(val, size):
    return ''.join([chr(int(x,2)) for x in nsplit(binvalue(val, size), 8)])


class SteganoApplication(TCPApplication):
    def __init__(self):
        TCPApplication.__init__(self)
        
        #For receiving purposes
        self.reassembled_stream = ""
        self.reception_finished = False
    
    def packet_received(self, packet, **kwargs):
        print("Regular data:",packet)
        
    def hidden_chunk_received(self, chunk, **kwargs):
        print("Hidden chunk:",chunk)
        self.reassembled_stream += chunk

    def hook_incoming(self, packet, **kwargs):
        ''' While the DF flag is  not set there is an hidden stream to receive from the server '''
        if not self.reception_finished:
            if packet.flags == 2 or packet.flags == 18: #Receive the first ISN of the remote host
                self.hidden_chunk_received(int_to_string(packet.seq,32)) #32 bits
            self.hidden_chunk_received(int_to_string(kwargs["IP"]["id"], 16))
            
            if kwargs["IP"]["flags"] == 2: #End of transfer
                print "Covert message: ", self.reassembled_stream
                self.reception_finished = True

    
    def hook_outgoing(self, packet, **kwargs):
        return packet, kwargs 


if __name__ =="__main__":
    stack = PyStack()
    stack.run(doreactor=False)
    
    steganoclient = SteganoApplication()
    stack.register_tcp_application(steganoclient)
    
    steganoclient.connect("192.168.1.38", 7777)
    
    steganoclient.send_packet("Hello")
    steganoclient.send_packet("world")
    steganoclient.send_packet("\n")
    steganoclient.send_packet("I")
    steganoclient.send_packet("try")
    steganoclient.send_packet("this.")
    steganoclient.send_packet("And this is")
    steganoclient.send_packet("a")
    steganoclient.send_packet("test")
    steganoclient.send_packet("of")
    steganoclient.send_packet("steganography")
    steganoclient.send_packet("and")
    steganoclient.send_packet("that's")
    steganoclient.send_packet("it.")
    
    import time
    time.sleep(3)
    steganoclient.close()
    stack.stop()
