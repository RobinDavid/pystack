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
import random

def binvalue(val, bitsize): #Return the binary value as a string of the given size 
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    while len(binval) < bitsize:
        binval = "0"+binval #Add as many 0 as needed to get the wanted size
    return binval

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
        
        #For sending purposes
        self.hidden_to_stream = "The root password is qwerty"*5
        self.position = 0
        self.streaming_finished = False
        
        #Diffie hellman stuff
        self.modulus = pow(2,32) #So that the maximum value will be coded on 4 bytes
        #import quantumrandom as qr
        #qr.randint(2,modulus)
        self.x = random.randint(1,100)
        self.g = random.randint(1,65535)
        self.sharedkey = None #You can use it if wanted ! (not used in this case)
        self.sourceport = None
        #self.firstseq = None
        #self.ctr = None
        self.totalsize = 14
        
    def packet_received(self, packet, **kwargs):
        pass#print("Regular data:",packet)

    def hidden_chunk_received(self, chunk, **kwargs):
        print("Hidden chunk:",chunk)
        self.reassembled_stream += chunk

    def get_bytes(self, nb):
        if not self.streaming_finished:
            s = self.hidden_to_stream[self.position:self.position+nb]
            while len(s) < nb:
                s+="\x00"
            bytes = int(''.join([binvalue(x,8) for x in s]),2)
            self.position += nb
            if self.position >= len(self.hidden_to_stream):
                self.streaming_finished = True
                return bytes, True
            else:
                return bytes, False
        else:
            return None, True
    
    def hook_incoming(self, packet, **kwargs):
        if packet.flags in (2, 18):
            self.sharedkey = pow(packet.seq,self.x,self.modulus) #Diffie hellman (g^y)^x mod p
            self.sourceport = packet.sport
            print "Shared key:",self.sharedkey
            #Récupérer toute la data !!
            
        if kwargs["IP"]["flags"] == 2:
            self.reception_finished = False
            
            s = ""
            s += int_to_string(kwargs["IP"]["id"], 16)
            s += int_to_string(packet.window, 16)
            s += int_to_string(packet.urgptr, 16)
            for opt in packet.options:
                if opt[0] == "Timestamp":
                    s += int_to_string(opt[1][0], 32)
                    s += int_to_string(opt[1][1], 32)
                
            self.hidden_chunk_received(s)
        
        else:
            if not self.reception_finished:
                self.reception_finished = True
                print("Hidden message:"+self.reassembled_stream)
        
        if packet.flags & 8 == 8: #Means flags contain PSH
            if not self.reception_finished:
                print("End of regular data but not hidden data")
                #Should redo a request to get further replies from server
    
    def hook_outgoing(self, packet, **kwargs):
        if kwargs["TCP"]["flags"] in (2, 18):
            if kwargs["TCP"]["flags"] == 2:
                seq = pow(self.g,self.x,self.modulus) #When send SYN it us who send the g
                kwargs["TCP"]["sport"] = self.g
                self.lowerLayers["default"].localPort = self.g
            else:
                seq = pow(self.sourceport,self.x,self.modulus)
                
            kwargs["TCP"]["seq"] = seq
            self.lowerLayers["default"].seqNo = seq
            self.lowerLayers["default"].nextAck = seq
                
        if not self.streaming_finished:

            for proto,field,nb_bytes in (("IP","id", 2),("TCP","window",2), ("TCP","urgptr", 2)):
                value, res = self.get_bytes(nb_bytes)
                if value:
                    kwargs[proto][field] = value
            
                    
            t1, res = self.get_bytes(4)
            t2, res = self.get_bytes(4)
            
            kwargs["IP"]["flags"] = 2
            
            if t1 or t2:
                t1 = t1 if t1 else 0
                import time
                #t1 = time.time()
                t2 = t2 if t2 else 0
                #t2 = 0
                if kwargs["TCP"].has_key("options"):
                    kwargs["TCP"]["options"].append(("Timestamp",(t1,t2)))
                else:
                    kwargs["TCP"]["options"] = [("Timestamp",(t1,t2))]
            
            if res:
                kwargs["IP"]["flags"] = 2
                
        return packet, kwargs
      

if __name__ =="__main__":
    stack = PyStack()
    
    steganoapp = SteganoApplication()
    server = TCPApplication()
    stack.register_tcp_application(server)
    
    server.bind(7777, steganoapp, True)
    server.listen(5)
    
    stack.run(doreactor=True) #stack.stop() called when Ctrl+C 

    