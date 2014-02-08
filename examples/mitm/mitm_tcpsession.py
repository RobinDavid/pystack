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

from scapy.all import IP

from pystack.layers.tcp_session import TCPSession, ACK, SYN
from pystack.layers.tcp_application import TCPApplication
import nfqueue

class SessionMITM(TCPSession):
    '''
    The topology is the following:
    Kernel(or A)  <---> Eve  <---->    Server
    seqNoa              seqNo
    ackNoa              ackNo
    nextAcka            nextAck
    '''

    pending = {} #Buffer of packet 
    seqNo = 0    #Eve sequence number
    ackNo = 0    #Eve acknowledgement number
    seqNoa = 0   #Kernel seqNo which is fooled
    ackNoa = 0   #Kernel ackNo which is fooled
    nextAcka = 0 #Value of the next expected ack for the Kernel
    nextAck = 0  #Value of the next expected ack for Eve
    come_from_kernel = None #Boolean to discriminate the origin of a packet 
    to_kernel = None        #Idem
    waitingEve = None       #Boolean activated when Eve is waiting for a reply
    waitingKernel = None    #Boolean activated when the kernel is waiting for a reply
    initialisation = True   #Boolean true while we have not received a packet(needed to initialize seqNo, ackNo..)
    last_timestamp = None   #If a timestamp was provided make sur to put it back in mangled packets
    last_window = None      #Used because the kernel is a bit touchy on the window value

    def __init__(self, interface, win):
        TCPSession.__init__(self, interface)
        self.win = win  #Qt window
        
    def outgoing_nfqueue_packet(self, dummy, packet):
        ''' Handler for outgoing packets coming from the nfqueue '''
     
        data = packet.get_data() #Recover raw data
        ippacket = IP(data)      #Convert bytes to a Scapy IP packet
        
        kwargs={'IP':ippacket.fields} 
        tcppacket = ippacket.payload #recover TCP packet
        if tcppacket.name != 'TCP':
            packet.set_verdict(nfqueue.NF_ACCEPT) #Accept if not TCP
        kwargs['TCP'] = tcppacket.fields
    
        print("\nOutgoing: "+tcppacket.summary())
        print("seqNoa: %s\t| seqNo: %s\nackNoa: %s\t| ackNo: %s\nnextAcka: %s\t| nextAck: %s" % (self.seqNoa,self.seqNo,self.ackNoa,self.ackNo,self.nextAcka,self.nextAck))
        
        if self.initialisation: #If we are in the initialisation stage. Initialise all variables
            self.localIP = ippacket.src
            self.remoteIP = ippacket.dst
            self.localPort = tcppacket.sport
            self.remotePort = tcppacket.dport
            self.connectionID=(self.localIP,self.localPort,self.remoteIP,self.remotePort)
            self.nextAcka = tcppacket.seq
            self.nextAck = tcppacket.seq
            self.seqNoa = tcppacket.seq
            self.seqNo = tcppacket.seq
            self.ackNoa = tcppacket.ack
            self.ackNo = tcppacket.ack
            self.initialisation = False #Finally switch the initialisation boolean to false
            print("Initialisation done")

        #Test below needed because MITM packets are also caught by the nfqueue, and in this case let them go.
        if self.pending.pop((ippacket.seq,ippacket.ack),None): # If packet not sent by 'pystack' (sent by kernel).
            self.come_from_kernel = False    
        else:
            self.come_from_kernel = True
        
        if self.come_from_kernel:
            if tcppacket.payload:
                modif = self.send_packet(tcppacket.payload.load, tcppacket.flags, **kwargs) #Call send_packet and get the resulting (modified) packet
            else:
                modif = self.send_packet(None, tcppacket.flags, **kwargs)
            print("About to send(kernel):",ippacket.fields)
            print("About to send(kernel):",tcppacket.fields)
            del tcppacket.chksum #Remove checksum so that it will be recalculated by Scapy when sent

            tcppacket.fields.update(modif) #Update packets with our modifications
            ippacket.payload = tcppacket #Put back the tcp packet into ip packet
            print("seqNoa: %s\t| seqNo: %s\nackNoa: %s\t| ackNo: %s\nnextAcka: %s\t| nextAck: %s" % (self.seqNoa,self.seqNo,self.ackNoa,self.ackNo,self.nextAcka,self.nextAck))
            p = str(ippacket)
            print("Post build: ",IP(p).fields)
            print("Post build: ",IP(p).payload.fields)
            l = len(p)
            packet.set_verdict_modified(nfqueue.NF_ACCEPT, p, l) #Accept the modified packet
        else:
            packet.set_verdict(nfqueue.NF_ACCEPT) #packet coming from pystack but caught by the nfqueue 
        
        
    def incoming_nfqueue_packet(self,dummy, packet):
        ''' Handler for incoming packets coming from the nfqueue '''
        data = packet.get_data()
        ippacket = IP(data)
        
        if self.initialisation:
            print("Packet received waiting for initialisation")
            return #I could have also initialised here but lazy of writing the code, prefer doing it when a packet is sent by the kernel
        
        kwargs={'IP':ippacket.fields}
        tcppacket = ippacket.payload
        if tcppacket.name != "TCP":
            packet.set_verdict(nfqueue.NF_ACCEPT) #Accept if not TCP
        
        print("\nIncoming: "+str(tcppacket.fields))
        print("seqNoa: %s\t| seqNo: %s\nackNoa: %s\t| ackNo: %s\nnextAcka: %s\t| nextAck: %s" % (self.seqNoa,self.seqNo,self.ackNoa,self.ackNo,self.nextAcka,self.nextAck))

        p = self.packet_received(tcppacket, **kwargs) #If a packet is return accept the modified packet otherwise just drop it
        if p: #If a packet is returned it means it should be forwarded to the kernel
            del p.chksum #I think it's good !
            ippacket.payload = p
            packet.set_verdict_modified(nfqueue.NF_ACCEPT, str(ippacket), len(ippacket))
        else:
            packet.set_verdict(nfqueue.NF_DROP)
            print("Packet dropped !")



    def send_packet(self, packet, flags=ACK, **kwargs):
        ''' Call when a packet is about to be sent either by kernel or Eve '''
    
        if self.initialisation:
            print("Cannot send packet while hadn't hooked a first packet")
            return
        
        #--- Coming from send_packet
        fields = {}
        fields["flags"] = flags
        
        if flags == SYN: #If SYN packet put our own MSS in option
            fields["options"] = [('MSS', self.local_mss)]
        #---------------------------
        
        if self.come_from_kernel: #If the packet come from the kernel, alter it's synchro to match ours
            if (self.seqNoa != (self.nextAcka - (self.seqNo - self.seqNoa))) and (self.nextAcka > self.nextAck): # A genuine packet has already been sent
                self.seqNoa = self.seqNo - self.seqNoa
                self.ackNoa = self.ackNo - self.ackNoa
                self.seqNo = self.nextAcka
            elif self.nextAck > self.nextAcka: # Eve has already sent unacked packet (so take nextAck as basis)
                self.seqNo = self.nextAck
                self.nextAcka = self.nextAck
                #self.seqNoa = packet.seq
                #self.ackNoa = packet.ack
        else: #Sent by Eve
            if self.seqNo != self.nextAck: #Comme from attacker and a genuine packet has been sent
                self.seqNo = self.nextAck
            elif self.seqNo != self.nextAcka:# Comme from attacker and a fake packet has already been sent
                self.seqNo = self.nextAcka
                self.nextAck = self.nextAcka
            
        if packet: #Update the right nextAck attribute depending of either the packet come from the kernel or not
            if self.come_from_kernel:
                self.nextAcka += len(packet)
            else:
                self.nextAck += len(packet)
        else: #There is no packet so juste acknowledge if not already ack
            if flags != ACK: 
                if self.come_from_kernel: # juste incremente nextAcka because 
                    self.nextAcka += 1
                else:
                    self.nextAck += 1 # incremente of one
        
        if self.come_from_kernel: #update seq,ack so that nfqueue will be able to accept the packet
            #All the other fields should be allright
            fields["seq"] = self.seqNo
            fields["ack"] = self.ackNo
            self.come_from_kernel = False
            self.last_window = kwargs["TCP"]["window"]
            if packet:
                self.win.kernel_data_sent(packet)
            return fields
        else: #Come from Eve so compute all fields and use the regular method to transmit the packet (transfer_packet)
            fields["sport"] = self.localPort
            fields["dport"] = self.remotePort
            fields["seq"] = self.seqNo  #Cause we do no send data
            fields["ack"] = self.ackNo
            if not kwargs.has_key("IP"):
                kwargs["IP"] = {}
            kwargs['IP']["src"] = self.localIP
            kwargs['IP']["dst"] = self.remoteIP if self.remoteIP else kwargs["IP"]["src"]
            kwargs['IP']['flags'] = 2
            if self.last_timestamp:
                value = [('NOP', None), ('NOP', None), ("Timestamp",(int(time.time()),self.last_timestamp))]
                fields["options"] = value
            if self.last_window:
                fields['window'] = self.last_window
            if kwargs.has_key("TCP"):
                kwargs["TCP"].update(fields)
            else:
                kwargs["TCP"] = fields
            fields.pop('options') #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            #-----------------------------------
            self.pending[(fields["seq"],fields["ack"])] = None #Queue headers to do nothing in nfqueue when received
            print("About to send(mitm):")
            print("seqNoa: %s\t| seqNo: %s\nackNoa: %s\t| ackNo: %s\nnextAcka: %s\t| nextAck: %s" % (self.seqNoa,self.seqNo,self.ackNoa,self.ackNo,self.nextAcka,self.nextAck))

            self.transfer_packet(packet, **kwargs)
    
    
    
    def packet_received(self, packet, **kwargs):
        ''' Call when a packet is received whatever the packet is for Eve or the Kernel. '''
        
        if packet.name == "TCP":
            self.upperLayers["Raw"].hook_incoming(packet, **kwargs) #Assume upperlayer is a tcp application
            #print self.state, packet.flags, packet.summary()
            if packet == self.lastPacket:
                print("Drop duplicate")
                return
            
            if (packet.ack == self.nextAcka) and (self.nextAcka != self.nextAck): #Receive a packet for kernel because ack = nextAcka (B acknowledge a packet of the kernel)
                self.nextAck = packet.ack
                self.to_kernel = True
                if len(packet.payload) == 1460:
                    self.waitingKernel = True
                else:
                    self.waitingKernel = False
                    
            elif packet.ack == self.nextAck and self.nextAck != self.nextAcka: #Receive a packet for Eve because ack = nextAck
                if len(packet.payload) == 1460:
                    self.waitingEve = True
                else:
                    self.waitingEve = False
                    
                if self.nextAcka < self.nextAck: #Update nextAck value of A anyway (otherwise cannot know who the next packet is for)
                    self.nextAcka = self.nextAck
            
            elif packet.ack == self.nextAcka and self.nextAcka == self.nextAck: #Don't know for who this packet is
                if self.waitingEve and not self.waitingKernel: #If Eve waiting for a packet consider it is for her(us)
                    if len(packet.payload) == 1460:
                        self.waitingEve = True
                    else:
                        self.waitingEve = False
                    print("Still for Eve")
                elif self.waitingKernel and not self.waitingEve: #If kernel is waiting for a packet consider it is for it
                    self.to_kernel = True
                    if len(packet.payload) == 1460:
                        self.waitingKernel = True
                    else:
                        self.waitingKernel = False
                elif self.waitingKernel and self.waitingEve: #Worst case both are waiting a packet cannot know. For the moment does nothing
                    print("Arghh !")
                    #Put back waiting for both to false ?
                else:
                    print("Gratuitous packet !")
                    self.to_kernel = True #Consider gratuitous packet for kernel
            
            elif packet.ack != self.nextAcka and self.nextAcka == self.nextAck: #ack value different from both nextAck and nextAcka
                print("Weird !")
            
            else: #Impossible case in theory
                print("What ?")
        
            if self.to_kernel:#If to_kernel update seqNoa and ackNoa by the diff value
                self.seqNoa = packet.ack - (self.seqNo - self.seqNoa)
                self.ackNoa = packet.seq - (self.ackNo - self.ackNoa)
                
            self.seqNo = packet.ack #Update seqNo and ackNo anyway (like in normal case)
            self.ackNo = packet.seq
            
            #--- taken from packet_received
            if packet.haslayer("Padding"): #Remove any padding if present to donot interfer with ack
                packet["Padding"] = None
            
            if packet.payload: #if there is a payload update ackNo and ackNoa in consequence
                self.ackNo += len(packet.payload)
                if self.to_kernel:
                    packet.seq = self.ackNoa
                    self.ackNoa += len(packet.payload)
            else:
                if packet.flags != ACK: #If we need to ack. add 1 to ackNo and ackNoa
                    self.ackNo += 1
                    if self.to_kernel:
                        packet.seq = self.ackNoa
                        self.ackNoa += 1
            
            if self.nextAck:
                if self.nextAck != self.seqNo:
                    print("Host didn't acknowledge all datas Expected:", self.nextAck, "("+str(self.seqNo)+")")
                    #Resend hoping the remote host will acknowledge all the packet??
            self.lastPacket = packet
            self._process_options(packet)           
                    
            if self.to_kernel:
                self.to_kernel = False
                packet.ack = self.seqNoa #Put back ack in packet (packet.seq already done)
                if packet.payload:
                    self.win.kernel_data_received(packet.payload.load)
                print("Packet forwarded to kernel")
                return packet
            else: #The packet is for Eve so call target
                self.state.packet_received(packet, **kwargs)
                return None #Return None so that the packet will be dropped
            
        elif packet.name == "Raw":  #Put back else afterward
            target = self.upperLayers.get(packet.name, self.upperLayers["default"])
            kwargs['id'] = self.connectionID
            target.packet_received(packet.load, **kwargs)
        
    def _process_options(self, packet):
        #self.last_window = packet.window
        if packet.options:
            for k, v in packet.options:
                if k == "Timestamp":
                    self.last_timestamp = v[0]


class MITMApplication(TCPApplication): #The TCPApplication associated with the MITM does nothing especially
    def __init__(self, win):
        TCPApplication.__init__(self)
        self.win = win
    
    def packet_received(self, packet, **kwargs):
        self.win.mitm_data_received(packet)
    
    def send_packet(self, packet, **kwargs):
        self.win.mitm_data_sent(packet)
        TCPApplication.send_packet(self, packet, **kwargs)
