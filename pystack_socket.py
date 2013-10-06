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

from _socket import *

from layers.tcp_application import TCPApplication
from pystack import PyStack
from layers.udp_application import UDPApplication


class _TCPSocket(TCPApplication):
    """
    Internal class to wrap TCPApplication into
    """
    def __init__(self):
        TCPApplication.__init__(self)


class _UDPSocket(UDPApplication):
    """
    Internal class to wrap UDPApplication into
    """
    def __init__(self):
        UDPApplication.__init__(self, None)


class socket:
    """
    socket class that will replace the genuine one located in _socket
    """
    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, app=None):
        self.app = None
        self.blocking = True
        self.stack = PyStack()
        if family not in (AF_INET, AF_INET6, AF_UNIX):
            raise error("Address family not supported by protocol "+family)
        else:
            self.family = family
        if type not in (SOCK_DGRAM, SOCK_STREAM):#SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET):
            raise error("Invalid argument "+type)
        else:
            self.type = type
            if app:
                self.app = app
            else:
                if type == SOCK_STREAM:
                    self.app = _TCPSocket()
                elif type == SOCK_DGRAM:
                    self.app = _UDPSocket()
        self.proto = proto
        if not app:
            if type == SOCK_STREAM:
                self.stack.register_tcp_application(self.app)
            elif type == SOCK_DGRAM:
                self.stack.register_udp_application(self.app)
            self.stack.run(doreactor=False)
    
    def accept(self):
        """accept a connect in case of TCP Socket, raise an error for UDP"""
        if self.type == SOCK_DGRAM:
            raise error("[Errno 95] Operation not supported")
        else:
            app = self.app.accept()
            news = socket(AF_INET, SOCK_STREAM, 0, app, self.blocking)
            return news, app.get_conn_addr()

    def bind(self, (host, port)):
        """Bind the application on the given port regardless of if this is an UDP or TCP socket"""
        if self.type == SOCK_DGRAM:
            if not self.stack.is_udp_port_free(port):
                raise error("[Errno 98] Address already in use")
        elif self.type == SOCK_STREAM:
            if not self.stack.is_tcp_port_free(port):
                raise error("[Errno 98] Address already in use")
        self.app.bind(port, self.app, True) #send ip when the stack will listen on all interfaces

    def close(self):
        """Call the close function of the app"""
        return self.app.close()

    def connect(self, (host, port)):
        """Call connect of the app (also valid for UDP)"""
        return self.app.connect(host, port)

    def connect_ex(self, (host, port)):
        """See real socket module for info"""
        if self.app.connect(host, port):
            return 0
        else:
            return 1

    def fileno(self):
        """Should be implemented in order to fake socket class. Does not do what expected may imply
        the app to crash if called."""
        print("Fileno called !")
        return 1

    def getpeername(self):
        """ Return the remote IP, port of the peer """
        return self.app.get_conn_addr()
    
    def getsockname(self):
        """ Return local IP, port"""
        return self.app.get_self_addr()
    
    def getsockopt(self, level, optname, bufflen=None):
        """Not implemented but needed to fake socket class"""
        print("getsocketopt called!")
        return None
    
    def ioctl(self, control, option):
        """Not implemented"""
        print("ioctl called !")
        return None
    
    def listen(self, backlog=0):
        """Call app listen method of TCPApplication"""
        if self.type == SOCK_DGRAM:
            raise error("[Errno 95] Operation not supported")
        else:
            self.app.listen(backlog)
    
    def makefile(self, mode=None, bufsize=None):
        """Not implemented"""
        print("Makefile is called !")
        return None

    def recv(self, bufsize, flags=0):
        """ Read informations received in the TCPApplication"""
        if self.blocking:
            while True:
                data = self.app.fetch_data(bufsize)
                if data:
                    return data
        else:
            return self.app.fetch_data(bufsize)

    def recvfrom(self, bufsize, flags=0):
        """Return information received in the socket, but also the originating peer"""
        if self.blocking:
            while True:
                elt = self.app.fetch_data_from(bufsize)
                if elt is not None:
                    if elt[2] != "":
                        return (elt[2], (elt[0], elt[1]))
        else:
            elt = self.app.fetch_data_from(bufsize)
            return(elt[2], (elt[0], elt[1]))

    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        """Write received bytes in the given buffer. (not tested)"""
        elt = self.recvfrom(nbytes)
        buffer += elt[0]
        return (len(elt[0]), elt[1])
    
    def recv_into(self, buffer, nbytes=None, flags=0):
        """Write received bytes in the given buffer. (not tested)"""
        data = self.recv(nbytes)
        buffer += data
        return len(data)

    def send(self, string, flags=0): #Normally should check that all data has been sent
        """Send the given data in the socket"""
        self.app.send_packet(string)
        return len(string)
    
    def sendall(self, string, flags=0):
        """Also send the given data in the socket"""
        self.app.send_packet(string)
        return None
    
    def sendto(self, string, address):
        """Send data to the given host. TCP ignore address. UDP send to the right hosts"""
        if self.type == SOCK_STREAM:
            self.app.send_packet(string)
        elif self.type == SOCK_DGRAM:
            fields = {"IP":{}, "UDP":{}}
            fields["IP"]["dst"] = address[0]
            fields["UDP"]["dport"] = address[1]
            self.app.send_packet(string, **fields)
    
    def setblocking(self, flag):
        """Set a boolean to make read write blocking or not"""
        if flag == 1:
            self.blocking = True
        elif flag == 0:
            self.blocking = False
    
    def settimeout(self, flag=None):
        """Not implemented. Define binary a timeout for blocking read/write"""
        if flag is None:
            self.blocking = True
        else:
            if int(flag) == 0:
                self.blocking = False
            else:
                self.blocking = True

    def gettimeout(self):
        """Return the if blocking or not"""
        return 1 if self.blocking else 0
    
    def setsockopt(self, level, optname, value):
        """Not implemented"""
        print("setsockopt called !")
        return None
    
    def shutdown(self, how):
        """Not implemented"""
        pass

    def stop(self): #Added by me to stop the stack
        """Stop the associated application"""
        self.stack.stop()

#----------------------
#------ Fonctions -----
#----------------------
def create_connection(address, timeout=None, source_address=None):
    """Create a connection and return the socket connected"""
    print("Create connectionc called !")
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(address)
    return sock

def gethostname():
    """Return the hostname"""
    hostname = open("/etc/hostname","r").readline()
    hostname = hostname.splitlines()[0]
    return hostname

#--------------------
#----- Constants ----
#--------------------
_GLOBAL_DEFAULT_TIMEOUT = object()
'''
AF_APPLETALK = 5
AF_ASH = 18
AF_ATMPVC = 8
AF_ATMSVC = 20
AF_AX25 = 3
....
'''
    
if __name__ == "__main__":
    
    s = socket(AF_INET, SOCK_STREAM)
    '''
    s.bind(("localhost", 8888))
    s.listen(2)
    cli, addr = s.accept()
    
    print(addr)
    
    cli.send("COcou")
    
    print("--")
    
    print(cli.recvfrom(512))
    
    cli.close()
    '''
    if s.connect(("www.google.fr", 80)):
        req = "GET / HTTP/1.1\r\nHost: www.google.fr\r\nConnection: Close\r\n\r\n"
        s.send(req)
        data = s.recv(15)
        print(data) # on affiche la reponse
    else:
        print("NOT CONNECTED !")
    s.close()
    
    s.stop() #Stop stack