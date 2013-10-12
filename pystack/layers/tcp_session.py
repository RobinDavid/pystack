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
import time
import re
import random

from scapy.all import get_if_addr

from pystack.layers.layer import Layer
from pystack.kernel_filter import block_outgoing_packets, unblock_outgoing_packets
from pystack.layers.tcp_application import TCPApplication
import transversal_layer_access

CWR = 128
ECE = 64
URG = 32
ACK = 16
PSH = 8
RST = 4
SYN = 2
FIN = 1
'''
FINACK = 17
SYNACK = 18
PSHACK = 24
RSTACK = 20
'''

def _has_flags(packet_flags, flags):
    """Check the existence of a flag using the decimal value"""
    return packet_flags & flags == flags

def _has_only_flags(packet_flags, flags, excluded_flags):
    """Generic method to check if a flag is activated using the decimal value"""
    return packet_flags & flags == flags and packet_flags & excluded_flags == 0

class TCPSession(Layer):
    """
    TCPSession contains the core methods to deal with a lot of cases that can
    be met with TCP. This class mainly implement methods to connect, bind and close
    a TCP session with a remote host. At every moment a TCP session have a standardised
    state from CLOSED, ESTABLISHED, ..
    This class also keeps at every moment all the variables needed in order to process
    TCP packets like sequence number, acknowledgement number, port ..
    """
    
    def __init__(self, interface):
        """
        Init initialise all the variable either if there are not used (e.g: 
        server variable when used as a client). Note: The default state is Closed
        """
        Layer.__init__(self)
        self.name = "TCP" #Should stay here ! (otherwise will override real tcp layer in transversal_layer_access)
        self.ipregex = re.compile("^(\d{1,3}.){3}.\d{1,3}$")
        self.state = State_CLOSED(self)
        self.interface = interface
        self.localIP = get_if_addr(interface)
        self.localPort = None
        self.remoteIP = None
        self.remotePort = None
        self.connectionID = None
        #--Server related variables
        self.connections = []  #Used when server to know how many clients are connected ..
        self.nbconntoaccept = 0
        self.currentconnection = 0
        self.newinstance = None  #When client connect either we send him on the same application or create a new instance
        #----
        self.seqNo = 0
        self.ackNo = 0
        self.toAck = 0
        self.nextAck = 0
        self.lastPacket = None
        self.local_mss = 1460 #TODO: change it to be dynamic (RFC 879 default value is 536
        self.remote_mss = None
        self.syn_retries = int(open("/proc/sys/net/ipv4/tcp_syn_retries", "r").read())
        
    def packet_received(self, packet, **kwargs):
        """
        The more important thing with this method is that for each packet
        this method can be called twice. The first time by the lower layer and the
        packet is TCP. Then the packet is processed and packet_received is possibly
        called once again with the packet decapsulated (in Raw). When a TCP packet
        is received seq and ack value are updated when the packet_received method
        of the current state of the connection is called to know what to do with 
        the current packet.
        """
        if packet.name == "TCP":
            self.upperLayers["Raw"].hook_incoming(packet, **kwargs) #Assume upperlayer is a tcp application
            #print self.state, packet.flags, packet.summary()
            if packet == self.lastPacket:
                print("Drop duplicate")
                return
            
            '''
            self.seqNo = packet.ack
            self.ackNo = packet.seq
            
            if packet.payload:
                self.toAck += len(packet.payload.load)
            '''
            self.seqNo = packet.ack
            #self.nextAck = self.seqNo ?
            self.ackNo = packet.seq
            
            if packet.haslayer("Padding"): #Remove any padding if present to donot interfer with ack
                packet["Padding"] = None
            if packet.payload: #Already prepare the next acknowledgement number
                self.ackNo += len(packet.payload)
            else:
                if packet.flags != ACK:
                    self.ackNo += 1  #Acknowledge everything which is not a pure ack
            
            if self.nextAck:
                if self.nextAck != self.seqNo:
                    print("Host didn't acknowledge all datas Expected:", self.nextAck, "("+str(self.seqNo)+")")
                    #Resend hoping the remote host will acknowledge all the packet??
            self.lastPacket = packet
            self._process_options(packet)
            self.state.packet_received(packet, **kwargs)
            
        elif packet.name == "Raw":  #Put back else afterward
            target = self.upperLayers.get(packet.name, self.upperLayers["default"])
            kwargs['id'] = self.connectionID
            target.packet_received(packet.load, **kwargs) 
            
    def connect(self, ip, port):  #Ajouter support du dns
        """
        This method try to connect to the given ip and port. If the
        TCP session is not CLOSED the operations are aborted. Else a local
        port is generated, an entry is added in iptables to preven the kernel
        to disturbe our connection and then a SYN packet is sent. Then the
        connection state is switched to SYN_SENT. The method will then loop
        for 20 seconds checking if the state has changed to ESTABLISHED. If 
        not it means that a problem occured and everything is rolled back.
        """
        if isinstance(self.state, State_CLOSED):
            self.localPort = random.randrange(1200, 65535)
            self.remoteIP = ip
            self.remotePort = port
            
            if not re.match(self.ipregex, ip): #Then this is a dn
                realip = transversal_layer_access["DNS"].nslookup(ip)
                if realip:
                    self.remoteIP = realip
                else:
                    raise Exception("[Errno -5] No address associated with hostname")
            
            #starting from here remoteIP contains the destination IP not DN or whatever
            block_outgoing_packets('tcp', None, None, self.remoteIP, port)
            self.connectionID = (self.remoteIP, self.remotePort, self.localIP, self.localPort)  #Switch order because we are interested in receiving incoming packet so src dst is switch
            self.lowerLayers["default"].register_upper_layer(self.connectionID, self)
            self._send_SYN()
            self.switch_state(State_SYN_SENT(self))
            #---- Wait for the connection to be established ----
            
            exponential_backoff_values = [3*pow(2, x) for x in range(self.syn_retries)]  #Precompute waiting intervals
            for timeout in exponential_backoff_values:
                instant = time.time()
                while (instant + timeout > time.time()):
                    if isinstance(self.state, State_ESTABLISHED):
                        return True
                self._send_SYN()
            
            #We have not received syn/ack so rollback connection
            unblock_outgoing_packets('tcp', None, None, self.remoteIP, port)
            self.lowerLayers["default"].unregister_upper_layer(self.connectionID)
            return False #No connection can occur if port is not open, arp request failed..
            #----------------------------------------------------
        else:
            print("Not in consistent state ("+str(self.state)+")")
            return False
    
    def bind(self, port, app=None, newinstance=False):
        """
        The bind method is quite ligthweight. It justs register
        itself to the TCP protocol as a handler and an entry is added
        to iptables to prevent the Hosting host to reply with RST.
        Note app and newinstance define on which TCPApplication client
        connections should be redirected and if the TCPApplication should
        be forked for every client or not.
        """
        self.app = app if app else TCPApplication()
        self.newinstance = newinstance
        self.localPort = port
        block_outgoing_packets("tcp", self.localIP, self.localPort, None, None)
        self.connectionID = (self.localIP, self.localPort)
        self.lowerLayers['default'].register_upper_layer(self.connectionID, self)

    def listen(self, nb=0):
        """
        This method basically just switch the current
        state from CLOSED to LISTEN so that SYN request will
        be handled.
        """
        if isinstance(self.state, State_CLOSED):
            self.nbconntoaccept = nb
            self.switch_state(State_LISTEN(self))
        else:
            print("Not in consistent state ("+str(self.state)+")")
    
    def accept(self):
        """
        From a server point of view every client connections are hold
        in the connections attribute. When accept is called the method start
        by flushing all CLOSED connections from the connections list. Then it
        waiting for a connection to be appended to the list to return it. (when
        the currentconnection value is changed)
        """
        #-- Remove closed connection located before the current "cursor" 
        size = len(self.connections)
        indices = []
        for i in range(self.currentconnection):
            if isinstance(self.connections[i].state, State_CLOSED):
                indices.append(i)
        self.connections = [x for x in self.connections if x not in indices]
        self.currentconnection = self.currentconnection - (size - len(self.connections))
        #---------------------------
        while not self.currentconnection+1 == len(self.connections):
            time.sleep(1)
        self.currentconnection += 1
        return self.connections[self.currentconnection-1].upperLayers["Raw"]  #Return de application level instead of the session
    
    def close(self):
        """
        For a client will send a FIN packet and switch to FIN_WAIT1.
        For a server will send a FIN packet for every clients in order 
        to unregister itself from the TCP layer
        """
        if isinstance(self.state, State_ESTABLISHED):
            self._send_FIN()
            self.switch_state(State_FIN_WAIT_1(self))
        elif isinstance(self.state, State_LISTEN):
            for session in self.connections:
                if isinstance(session.state, State_ESTABLISHED):
                    session._send_FIN()
                    session.switch_state(State_FIN_WAIT_1(session))
            unblock_outgoing_packets('tcp', self.localIP, self.localPort, None, None)
            self.unregister_upper_layer(self.connectionID)
            self._unregister_app_layer(self.connectionID)
        else:
            print("Not in consistent state to close")

    def unregister_upper_layer(self, name):
        """Used to remove himself from the lower layer"""
        self.lowerLayers["default"].unregister_upper_layer(name)
    
    def _unregister_app_layer(self, name):
        """Used to remove himself from the upper layer"""
        if self.upperLayers.has_key("Raw"):
            if self.upperLayers["Raw"].lowerLayers.has_key(name):
                self.upperLayers["Raw"].lowerLayers.pop(name)
   
    def switch_state(self, state):
        """
        Switch to the given state. State should
        implement State
        """
        self.state = state

    def _call_connection_made(self):
        """Called when the connection is made. It call
        the connection_made from the application layer.
        """
        self.upperLayers["Raw"].connection_made()  #Assume that the Raw upper layer is an TCP Application and so contains the so called method
    
    def _process_options(self, packet):
        """
        This method deal with options present in TCP packets. It is
        common for every state and is called before packet_received of
        the state.
        """
        if not isinstance(self.state, State_LISTEN):  #Process options in every state but listen (rfc)
            for k, v in packet.options:
                if k == "MSS":
                    self.remote_mss = v
                elif k == "Timestamp":
                    pass#print "Timestamp received", v
    
    def send_packet(self, packet, flags=ACK, **kwargs):
        """
        This method is one of the most critical. Every TCP packet are sent
        through this method. This method basically deal with all the flags and
        is in charge to incremente sequence number. In addition it sets all the
        TCP fields in order to generate the packet. It increment the ack value
        of the data size of the previously received packet.  
        """
        fields = {}
        fields["flags"] = flags
        
        if flags == SYN:
            fields["options"] = [('MSS', self.local_mss)]
        
        '''
        if packet_received:
            if packet_received.payload.name == "Raw":
                data = packet_received.payload.load
                self.ackNo += len(data)
            else:
                self.ackNo +=1
        '''
        '''
        if self.toAck:
            #TODO: Add the flag ACK if not activated (FIN..)
            self.ackNo += self.toAck
            self.toAck = 0
        else:
            if packet_received: #Ack +1 only if we previously received a packet
                self.ackNo += 1
        '''
        #It is the same but in reverse nextAck should be data if existing +1 instead or +0 if pure ack
        if packet:
            self.nextAck += len(packet)
        else:
            if flags != ACK: #Excpect the remote host to ack every packet but pure Ack
                self.nextAck += 1

        fields["sport"] = self.localPort
        fields["dport"] = self.remotePort
        fields["seq"] = self.seqNo  #Cause we do no send data
        fields["ack"] = self.ackNo
        
        if not kwargs.has_key("IP"):
            kwargs["IP"] = {}
        kwargs['IP']["src"] = self.localIP
        kwargs['IP']["dst"] = self.remoteIP if self.remoteIP else kwargs["IP"]["src"]
        
        if kwargs.has_key("TCP"):
            kwargs["TCP"].update(fields)
        else:
            kwargs["TCP"] = fields
        
        if self.remote_mss:
            mss = self.remote_mss if self.remote_mss <= self.local_mss else self.local_mss
        else:
            mss = self.local_mss
        if packet:
            if len(packet) > mss:
                fragments = self._nsplit(packet, mss)
                for i in range(len(fragments)):
                    kwargs['TCP']["seq"] = kwargs["TCP"]["seq"] + len(fragments[i-1]) if i != 0 else kwargs["TCP"]["seq"] #Do not addition length for the first packet
                    self.transfer_packet(fragments[i], **kwargs)
            else:
                self.transfer_packet(packet, **kwargs)
        else:
            self.transfer_packet(packet, **kwargs)


    def transfer_packet(self, packet, **kwargs):
        """
        Override the layer transfer_packet just to add the hook.
        """
        packet, kwargs = self.upperLayers["Raw"].hook_outgoing(packet, **kwargs) #Assume the Raw application is a tcp_application
        self.lowerLayers["default"].send_packet(packet, **kwargs)

    def _nsplit(self, s, n):#Split a list into sublists of size "n"
        return [s.load[k:k+n] for k in xrange(0, len(s), n)]

    def _send_SYN(self):
        """
        Generate the sequence number set the ack number and
        call send_packet with the appropriate flags
        """
        if not self.seqNo:  #Avoid regenerating a sequence number when resending the syn packet on connect
            self.seqNo = random.randrange(0, (2**32)-1)
        self.ackNo = 0
        self.nextAck = self.seqNo
        self.send_packet(None, SYN)

    def sendRST(self, packet, **kwargs):
        """Just send a reset packet to the remote host"""
        print "Send RST state:", str(self.state)
        self.send_packet(None, RST+ACK, **kwargs)
    
    def _send_SYNACK(self, packet):
        """
        Send a syn_ack packet. To do it, generate a sequence
        number and call send_packet with the SYNACK flags
        """
        self.seqNo = random.randrange(0, (2**32) - 1)
        self.nextAck = self.seqNo
        self.send_packet(None, SYN+ACK)
    
    def _send_ACK(self, packet=None, other=None):
        """Call send_packet with ACK flag activated"""
        self.send_packet(other, ACK)
    
    def send_data(self, packet, push=True, **kwargs):
        """
        Just call send_packet with datas. The nextAck indicator
        is also updated to the excpected value.
        """
        if self.seqNo != self.nextAck:
            self.seqNo = self.nextAck
            
        self.send_packet(packet, PSH+ACK if push else ACK, **kwargs)  #For now push always true because no upper layer call directly send_data
            
    def _send_FIN(self):
        """Send a FIN packet"""
        self.nextAck += 1
        self.send_packet(None, FIN)
    
    def _send_FINACK(self, packet):
        """Send a FIN_ACK packet"""
        self.nextAck += 1
        self.send_packet(None, FIN+ACK)
    

class State():
    """
    State class is the mother class that describe
    a state at a given moment. A state is just
    characterised by a name and should implement a 
    method called packet_received that will provide 
    the adapted state behavior for every packets
    """
    
    def __init__(self, session):
        """
        Init takes a session as class attribute to be
        able to interact with it in a two way interaction
        """
        self.session = session
    
    def packet_received(self, packet, **kwargs):
        """
        By default packet_received does nothing but
        printing the packet
        """
        print(repr(packet))


class State_CLOSED(State):
    """
    Any packets received on a Closed connection is
    being replied with a reset packet
    """
    
    def packet_received(self, packet, **kwargs):
        self.session.sendRST(packet, **kwargs)


class State_LISTEN(State):
    """
    A tcp session in Listen state only process SYN packet. When a SYN
    packet is received it checks that the number of connection to accept is
    not exceeded. If this is ok it creates another TCP session specific for
    this connection. Then it attachs it a TCPApplication either by forking
    it or not depending of the config. Then it switched the newly created
    connection to SYN_SENT state.
    """
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == SYN:  #Don't check if the dstport is the same because it has been check in tcp
            #--- Check we have not exceeded the number of connections
            count = 0
            for sess in self.session.connections:
                if not isinstance(sess.state, State_CLOSED):
                    count += 1
            if count >= self.session.nbconntoaccept:
                self.session.sendRST(packet, **kwargs)
                return
            #--------------------------------------------------
            session = TCPSession(self.session.interface)
            session.seqNo = packet.ack
            session.ackNo = packet.seq + 1
            session.localPort = packet.dport
            session.remoteIP = kwargs["IP"]["src"]
            session.remotePort = packet.sport
                             
            block_outgoing_packets('tcp', None, None, session.remoteIP, session.remotePort)
            
            connID = (session.remoteIP, session.remotePort, session.localIP, session.localPort)
            session.connectionID = connID
            
            self.session.lowerLayers["default"].register_layer_full(connID, session)
            if self.session.newinstance:
                newapp = self.session.app.__new__(type(self.session.app))
                newapp.__init__()
                session.register_layer(newapp)
                session.upperLayers["Raw"].hook_incoming(packet, **kwargs) #Cause if a new instance is created the SYN packet is received by the socket server in listen, and not the application itself so call hook again here
            else:
                session.register_upper_layer("Raw", self.session.app)
                self.session.app.register_lower_layer(session.connectionID, session)
                #session.register_layer_full("Raw", self.session.app)
            session._send_SYNACK(packet)
            session.switch_state(State_SYN_RCVD(session))
            self.session.connections.append(session)
        elif _has_flags(packet.flags, RST): #(TCP/IP illustrated Volume 2 p.999)
            pass  #Ignore the packet
        elif _has_flags(packet.flags, ACK):
            self.session.sendRST(packet, **kwargs)
        else:
            pass  #What should we do ?


class State_SYN_SENT(State):
    """
    When in SYN_SENT only process SYN_ACK packets by replying
    a ACK packet. It also switch the state to ESTABLISHED and call
    the session _call_connection_made method
    """
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == SYN+ACK: #Logical or but result is SYN + ACK
            self.session._send_ACK(packet)
            self.session.switch_state(State_ESTABLISHED(self.session))
            self.session._call_connection_made()
        elif packet.flags == SYN:
            print "Simultaneous open Arrrghhh !"
        elif _has_flags(packet.flags, RST): #(TCP/IP illustrated Volume 2 p.999)
            pass  #Ignore the packet
        elif _has_flags(packet.flags, ACK):
            self.session.sendRST(packet, **kwargs)
        else:
            pass  #What should we do ?


class State_SYN_RCVD(State):
    """
    When in SYN_RCVD only process ACK packets. Then
    switch the state to ESTABLISHED and call ConnectionMade
    """
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == ACK: #Ack
            self.session.switch_state(State_ESTABLISHED(self.session))
            self.session._call_connection_made()
        else:
            self.session.sendRST(packet, **kwargs)
        #Receive a FIN at this moment is legal (p.1052, TCP/IP Illustrated vol2)

class State_ESTABLISHED(State):
    """
    When the session is in the established state it should
    handle a lot's of different cases and react in consequences
    """
    
    def packet_received(self, packet, **kwargs):
        if _has_flags(packet.flags, FIN):
            self.session._send_FINACK(packet)
            #Forward data to application layer ?
            self.session.switch_state(State_LAST_ACK(self.session))
        elif _has_flags(packet.flags, RST):
            pass #What do we do with a reset flag ?
        elif _has_flags(packet.flags, ACK):
            if packet.payload: #Acknowledge if data has been sent
                self.session._send_ACK(packet)  #No delayed ack implemented, and should reply before 200ms RFC1122
            self.session.packet_received(packet.payload)  #By default will transfer it to the upper layer (Raw)
        else:
            self.session.sendRST(packet, **kwargs)


class State_FIN_WAIT_1(State):
    """
    When in FIN_WAIT expect a FIN and ACK packet. If
    it received a FIN_ACK packet it sends a ACK switch to closed
    and unregister itself from both the upper and the lower layer
    """
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == FIN:
            self.session.switch_state(State_FIN_WAIT_2(self.session))
            #self.session.packet_received(packet.payload)  #Can there be data in a FIN packet ?
        elif _has_flags(packet.flags, FIN+ACK):  #Received FIN and Ack in the same packet
            self.session._send_ACK() 
            self.session.switch_state(State_TIME_WAIT(self.session))#??
            #Directly remove the session do not switch to closed
            unblock_outgoing_packets('tcp', None, None, self.session.remoteIP, self.session.remotePort)
            self.session.unregister_upper_layer(self.session.connectionID)
            self.session._unregister_app_layer(self.session.connectionID)
            self.session.switch_state(State_CLOSED(self.session))  #Will never received any packet because connection unregistered from tcp layer
            #self.session.packet_received(packet.payload)  #Can there be data in a FIN packet ?
        else:
            if packet.payload: #Acknowledge if data has been sent
                self.session._send_ACK(packet)  #No delayed ack implemented, and should reply before 200ms RFC1122
            self.session.packet_received(packet.payload)  #Still forward data in case of ACK..

class State_CLOSE_WAIT(State):
    """
    This state is not implemented in the stack. The
    stack always send both FIN and ACK in the same packet
    """
    
    def packet_received(self, packet, **kwargs):
        pass


class State_FIN_WAIT_2(State):
    """
    In FIN_WAIT2 if the host send a FIN to session can be ended up
    sucessfully.
    """
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == FIN:
            self.session.switch_state(State_TIME_WAIT(self.session)) #??
            #Directly remove the session do not switch to closed
            unblock_outgoing_packets('tcp', None, None, self.remoteIP, self.remotePort)
            self.session.unregister_upper_layer(self.session.connectionID)
            self.session._unregister_app_layer(self.session.connectionID)
            self.session._send_ACK(packet)
            self.session.switch_state(State_CLOSED(self.session))
        else:
            self.session.sendRST(packet, **kwargs)


class State_LAST_ACK(State):
    """When in Last_ACK just wait for the final ack to close the connection"""
    
    def packet_received(self, packet, **kwargs):
        if packet.flags == ACK:
            #directly remove do not put to closed
            unblock_outgoing_packets('tcp', None, None, self.session.remoteIP, self.session.remotePort)
            self.session.unregister_upper_layer(self.session.connectionID)
            self.session._unregister_app_layer(self.session.connectionID)
            self.session.switch_state(State_CLOSED(self.session))
        else:
            print "would have sent a reset"
            #self.session.sendRST(packet)


class State_TIME_WAIT(State):
    """Not implemented state directly deleted (normally put to closed for few sec)"""
    pass