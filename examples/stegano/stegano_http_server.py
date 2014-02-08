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
import random
import re

from pystack.layers.tcp_session import TCPSession
from pystack.layers.tcp_application import TCPApplication
from pystack.pystack import PyStack

#Webserver imports
from twisted.web.server import Site
from twisted.web import static
from twisted.internet.abstract import FileDescriptor
from twisted.internet.abstract import _ConsumerMixin
import os


def binvalue(val, bitsize): #Return the binary value as a string of the given size 
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    return binval.zfill(bitsize)

def nsplit(s, n):#Split a list into sublists of size "n"
    return [s[k:k+n] for k in xrange(0, len(s), n)]

def int_to_string(val, size):
    return ''.join([chr(int(x,2)) for x in nsplit(binvalue(val, size), 8)])

class WebServer(_ConsumerMixin):
    ''' Class that allow to server a HTTP server on the given directory '''
    disconnecting = False #Required by twisted
    connected = True
    disconnected = False
    
    def __init__(self,tcpapp, path):
        _ConsumerMixin.__init__(self)
        self.app = Site(static.File(os.path.abspath(path))).buildProtocol("test")
        self.app.transport = self #Because we define self as transport we have to implement function normally called by twisted for a transport class
        self.tcpapp = tcpapp #tcpapp contain the TCPApplication !
        
    def packet_received(self, packet, **kwargs): #Will be called by the TCPApplication with genuine requests
        #self.lastclient = kwargs["id"]
        try:
            print("Request received")
            self.app.dataReceived(packet)
        except Exception, e:
            print("Something is wrong in the request:"+ str(e))
    
    def write(self, data):
        print "Data to send"
        self.tcpapp.send_packet(data)#Call the send_packet of the TCPApplication
    
    def getPeer(self):
        class X:
            host = "myHost"
            port = "myPort"
        return X()

    def getHost(self):
        return self.getPeer()
    
    def writeSequence(self, iovec):
        self.write("".join(iovec))

    def loseConnection(self):
        pass
        
    def getvalue(self):
        pass

class HiddenWebServer(WebServer):
    ''' Hidden Server that inherit WebServer but overwrite 'write' '''
    def __init__(self,tcpapp, path):
        WebServer.__init__(self, tcpapp, path)
    
    def write(self, data): 
        self.tcpapp.send_hidden_packet(data)#Overwrite write to call send_hidden_packet_instead of send_packet

class SteganoWebServer(TCPApplication):
    
    def __init__(self):
        TCPApplication.__init__(self)
        
        self.regular_site = WebServer(self, "sitetest") #Create instance of the genuine Webserver
        self.hidden_site = HiddenWebServer(self, "hiddensite") #Create the instance of the covert WebServer
        
        #For receiving purposes
        self.reassembled_stream = ""    #Will contain the covert data
        self.reception_finished = True
        
        #For sending purposes
        self.hidden_to_stream = ""      #Will contain covert data to stream
        self.position = 0               #Offset into data to send
        self.streaming_finished = True
        
        #Diffie hellman stuff
        self.modulus = 4294967291       #Nearest prime number from pow(2,32) (4294967296) stored on 4 bytes so that the maximum value will be coded on 4 bytes
        self.x = random.randint(1,100)  #Value used for diffie Hellman
        self.g = random.randint(1,65535)#Value used for diffie hellman
        self.sharedkey = None           #will contain Diffie Hellman key
        self.sourceport = None          #Source port that contain is used for diffie hellman
        self.key = None                 #Key hash of the sharedkey
        self.ctr_input = None           #Ctr value for input decipher algorithm
        self.ctr_output = None          #Ctr value for output cipher algorithm
        self.cipher_input = None        #Input decipher algorithm
        self.cipher_output = None       #Output cipher algorithm
        
    def packet_received(self, packet, **kwargs): #Regular data are handled normally (sent to the regular web server)
        self.regular_site.packet_received(packet, **kwargs)

    def hidden_chunk_received(self, chunk, **kwargs): #Call when covert data are received (forwarded to window)
        print("Hidden chunk:",chunk)
        self.reassembled_stream += chunk

    def send_hidden_packet(self, packet): #When covert data should be sent, just add them to the buffer
        self.hidden_to_stream += packet
        self.streaming_finished = False

    def get_bytes(self, nb): #Return the wanted number of bytes into the data to stream
        if not self.streaming_finished:
            s = self.hidden_to_stream[self.position:self.position+nb]
            while len(s) < nb:
                s+="\x00"
            bytes = s #int(''.join([binvalue(x,8) for x in s]),2)
            self.position += nb
            if self.position >= len(self.hidden_to_stream):
                self.streaming_finished = True
                self.position = 0
                return bytes, True
            else:
                return bytes, False
        else:
            return None, True
    
    def generate_keys(self, packet): #Generate all the cryptographic stuff
        self.sourceport = packet.sport #Used as g of diffie hellman exchange
        print "A(seq):",packet.seq,"  a:",self.x,"  mod:",self.modulus
        self.sharedkey = pow(packet.seq,self.x,self.modulus) #Diffie hellman (g^y)^x mod p
        print("Shared key:"+str(self.sharedkey))
        
        from Crypto.Hash import SHA256
        sha = SHA256.new()
        sha.update(str(self.sharedkey))
        self.key = sha.digest() #Now have a nice key of 256 bits
        
        from Crypto.Util import Counter
        self.ctr_input = Counter.new(128,initial_value=self.sharedkey)
        self.ctr_output = Counter.new(128,initial_value=self.sharedkey)
        
        from Crypto.Cipher import AES #Initialize symmetric ciphers
        self.cipher_input = AES.new(self.key, AES.MODE_CTR, counter=self.ctr_input)
        self.cipher_output = AES.new(self.key, AES.MODE_CTR, counter=self.ctr_output)

    def cipher(self,value): #Cipher the given value
        res = self.cipher_output.encrypt(value)
        final= int(''.join([binvalue(x,8) for x in res]),2)
        return final
    
    def decipher(self, value, size): #Decipher the given value
        value = int_to_string(value, size)
        final = self.cipher_input.decrypt(value)
        return final
    
    def hook_incoming(self, packet, **kwargs):
        ''' Call when a packet is received '''
        if packet.flags in (2, 18): #Normally never receive SYN-ACK
            self.generate_keys(packet)
        else:    
            if kwargs["IP"]["flags"] == 2: #While DF flag activated there is covert data to transmit
                self.reception_finished = False
                
                s = ""
                s += self.decipher(kwargs["IP"]["id"], 16) #Recover covert data stored in various fields
                s += self.decipher(packet.window, 16)
                s += self.decipher(packet.urgptr, 16)
                for opt in packet.options: #Even in timestamp option field
                    if opt[0] == "Timestamp":
                        s += self.decipher(opt[1][0], 32)
                        #s += int_to_string(opt[1][1], 32)
                    
                self.hidden_chunk_received(s)
            
            else:
                if not self.reception_finished:
                    self.reception_finished = True
                    self.hidden_site.packet_received(self.reassembled_stream, **kwargs) #Forward the deciphered request to the hiddenserver
                    self.reassembled_stream=""
                    print("Hidden message:"+self.reassembled_stream)
            
            if packet.flags & 8 == 8: #Means flags contain PSH
                if not self.reception_finished:
                    print("End of regular data but not hidden data")
                    #Should redo a request to get further replies from server
    
    def hook_outgoing(self, packet, **kwargs):
        if kwargs["TCP"]["flags"] in (2, 18):  #If we are still in the handshake 
            if kwargs["TCP"]["flags"] == 2:
                print "The server should not be launched as client !"
            else:
                print "SYNACK  sourceport:",self.sourceport
                seq = pow(self.sourceport, self.x,self.modulus)
                
            kwargs["TCP"]["seq"] = seq
            self.lowerLayers["default"].seqNo = seq
            self.lowerLayers["default"].nextAck = seq+1
              
        elif not self.streaming_finished: #If not in handshake and covert data still need to be sent
            size = 0
            for proto,field,nb_bytes in (("IP","id", 2),("TCP","window",2), ("TCP","urgptr", 2)): #Put our covert data in possible fields
                value, res = self.get_bytes(nb_bytes)
                if value:
                    kwargs["IP"]["flags"] = 2
                    size += 2
                    kwargs[proto][field] = self.cipher(value) #ciphering them
            
                    
            t1, res = self.get_bytes(4)
            size +=4
            
            if t1: #Also put covert data in timestamp if possible
                t1 = self.cipher(t1) if t1 else 0

                if kwargs["TCP"].has_key("options"):
                    kwargs["TCP"]["options"].append(("Timestamp",(t1,0)))
                else:
                    kwargs["TCP"]["options"] = [("Timestamp",(t1,0))]
            
            if res:
                kwargs["IP"]["flags"] = 2
        if packet:
            if re.search("</html>",packet.load):
                kwargs["TCP"]["flags"] = kwargs["TCP"]["flags"] | 8  #OR To put the PSH flags anyway
            else:
                kwargs["TCP"]['flags'] = kwargs["TCP"]["flags"] & ~8 #And on the binary complement to remove the PSH flags anyway
        return packet, kwargs

if __name__ == "__main__":

    stack = PyStack()

    steganoapp = SteganoWebServer()
    server = TCPApplication()
    stack.register_tcp_application(server)
    
    server.bind(80, steganoapp, True)
    server.listen(5)
    
    stack.run(doreactor=True)
