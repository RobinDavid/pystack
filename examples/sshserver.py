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
from twisted.internet.abstract import _ConsumerMixin
from twisted.conch import checkers, unix
from twisted.conch.openssh_compat import factory 
from twisted.conch.openssh_compat.factory import OpenSSHFactory
from twisted.cred import portal, checkers as chk

class MyFactory(OpenSSHFactory):
    #I need to create my factory because OpenSSHFactory fail when reading /etc/ssh and all keys
    #Because some are not recognised it return None but no test is made
    #So I just added "if key:" at the fourth last line of getPrivateKeys
   
    def getPrivateKeys(self):
        from twisted.python import log
        from twisted.python.util import runAsEffectiveUser 
        from twisted.conch.ssh import keys
        import os, errno
        privateKeys = {}
        for filename in os.listdir(self.dataRoot):
            if filename[:9] == 'ssh_host_' and filename[-4:]=='_key':
                fullPath = os.path.join(self.dataRoot, filename)
                try:
                    key = keys.Key.fromFile(fullPath)
                except IOError, e:
                    if e.errno == errno.EACCES:
                        # Not allowed, let's switch to root
                        key = runAsEffectiveUser(0, 0, keys.Key.fromFile, fullPath)
                        keyType = keys.objectType(key.keyObject)
                        privateKeys[keyType] = key
                    else:
                        raise
                except Exception, e:
                    log.msg('bad private key file %s: %s' % (filename, e))
                else:
                    if key: #Just to add this Fucking Line !
                        keyType = keys.objectType(key.keyObject)
                        privateKeys[keyType] = key
        return privateKeys

class SSHServer(TCPApplication, _ConsumerMixin):
    ''' TCPApplication that run a SSH server thank's to twisted functionalities '''
    disconnecting = False #Required by twisted
    connected = True
    disconnected = False
    buff = ""
    first_outpout = True
    
    def __init__(self):
        TCPApplication.__init__(self)
        _ConsumerMixin.__init__(self)

        #t = factory.OpenSSHFactory()
        t = MyFactory() #Use my factory instead of the original one
        t.portal = portal.Portal(unix.UnixSSHRealm()) #Instanciate all the needed stuff to create to protocol
        t.portal.registerChecker(checkers.UNIXPasswordDatabase())
        t.portal.registerChecker(checkers.SSHPublicKeyDatabase())
        if checkers.pamauth:
            t.portal.registerChecker(chk.PluggableAuthenticationModulesChecker())
        t.dataRoot = '/etc/ssh'
        t.moduliRoot = '/etc/ssh'

        t.startFactory()
        self.app = t.buildProtocol("lala")
        self.app.transport = self
        
    def connection_made(self):
        self.app.connectionMade()
        
    def packet_received(self, packet, **kwargs): #Override TCPApplication packet_received to call the dataReceived of twisted
        try:
            self.app.dataReceived(packet)
        except Exception, e:
            print("Something is wrong in the request:"+ str(e))
    
    def write(self, data):
        if self.first_outpout: #Buffer the first packet otherwise does not works (Odd I agree)
            self.buff = data
            self.first_outpout = False
            return
        elif self.buff != "":
            data = self.buff+data
            self.buff = ""
            
        while len(data) > 0:
            x = data[0:1000]
            data = data[1000:]
            #self.send_data(x)
            self.send_packet(x)
    
    def getPeer(self):
        class X:
            host = "myHost"
            port = "myPort"
        return X()

    def getHost(self):
        return self.getPeer()
    
    def writeSequence(self, iovec):
        self.write("".join(iovec))

    def logPrefix(self):
        return "pystackSSHServer"

    def setTcpNoDelay(self, tog):
        pass

    def loseConnection(self):
        pass
        
    def getvalue(self):
        pass

if __name__ =="__main__":
    from pystack.pystack import PyStack
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    stack = PyStack(iface=iface)
    
    sshserver = SSHServer()
    
    stack.register_tcp_application(sshserver)
    
    sshserver.bind(22, sshserver, newinstance=True)
    #Or echoserver.bind(5555) because by default new client are mapped on the same app without creating new instance
    sshserver.listen(5)
    
    stack.run(doreactor=True) #stack.stop() called when Ctrl+C 
    
    '''
    #---- Solution where we create our stack by hand ----
    from pystack.layers.ethernet import EthernetProtocol
    from pystack.layers.ip import IPProtocol
    from pystack.layers.arp import ARPProtocol
    from pystack.layers.tcp import TCPProtocol
    from pystack.layers.tcp_session import TCPSession
    interface = "eth0"
    eth = EthernetProtocol(interface)
    ip = IPProtocol()
    eth.register_layer(ip) #Enregistre aussi eth comme defaut pour ip
    arp = ARPProtocol(interface)
    eth.register_layer(arp)
    tcp = TCPProtocol()
    ip.register_layer(tcp)
    
    session = TCPSession(interface)
    tcp.register_layer(session)
    sshserver = SSHServer()
    session.register_layer(sshserver)
    
    sshserver.bind(22, app=sshserver, newinstance=True) #Need to create new Webserver instance for each client otherwise I don't why the twisted background fail after the second client (probably due to the fact it is really tricky)
    #app is the the tcp application were all clients will be bind
    #newinstance decide either or not we create a new app for every client or if we redirect them on the same
    
    sshserver.listen(2)
    
    eth.start_listening(doreactor=True)
    #Use the reactor system so the program hook on this call
    #-------------------------------------------------------
    '''
