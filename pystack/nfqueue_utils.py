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

import nfqueue
from subprocess import call
import threading
import time
import asyncore

AF_INET = 2

#payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(pkt2),len(pkt2))

class QueueAsync(asyncore.file_dispatcher, threading.Thread):
    def __init__(self, callback, num):
        threading.Thread.__init__(self)
        self._q = nfqueue.queue()
        self._q.set_callback(callback)
        self._q.fast_open(num, AF_INET)
        self.fd = self._q.get_fd()
        asyncore.file_dispatcher.__init__(self, self.fd, None)
        self._q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        
        self._stopevent = threading.Event()
    
    def handle_read(self):
        self._q.process_pending(5)
    
    def writable(self):
        return False
    
    def run(self):
        while not self._stopevent.isSet():
            #asyncore.loop(timeout=2)
            asyncore.poll(timeout=1.0)
            self._stopevent.wait(0.0)
        print "thread stopping"
        
    def stop(self):
        self._stopevent.set()

class NFQueueManager:
    
    def __init__(self):
        self.active_hooks = []
        self.active_threads = []
    
    def add_queue_rule(self, chain, param, queuenum):
        command= chain+" "+param+" -j NFQUEUE --queue-num "+str(queuenum)
        if call("iptables -t filter -A "+command,shell=True):
            print "Invalid iptables queue command:"+command
        self.active_hooks.append(command)
    
    def remove_queue_rule(self, chain, param, queuenum):
        command= chain+" "+param+" -j NFQUEUE --queue-num "+str(queuenum)
        if call("iptables -t filter -D "+command,shell=True):
            print "Invalid iptables queue command:"+command
        self.active_hooks.remove(command)
        
    def run_queue_blocking(self, callback, num):
        q = nfqueue.queue()
        q.set_callback(callback)
        q.fast_open(num,AF_INET) #Instead of : q.open() and q.bind(socket.AF_INET) and q.create_queue(12)
        try:
            time.sleep(1)
            q.try_run()
        except:
            q.unbind(AF_INET)
            q.close()
    
    def run_queue(self, callback, num):
        th = QueueAsync(callback, num)
        th.start()
        self.active_threads.append(th)
        return th
    
    def stop(self, th):
        self.active_threads.remove(th)
        th.stop()
        th.join()
        
    def stopall(self):
        for t in self.active_threads:
            t.stop()
            t.join()

        
if __name__ == "__main__":
    
    from scapy.all import IP
    
    def process(payload):
        data = payload.get_data()
        p = IP(data)
        print p.summary()
        payload.set_verdict(nfqueue.NF_ACCEPT)
    
    qm = NFQueueManager()
    qm.add_queue_rule("OUTPUT", "-p tcp --dport 4545", 12)
    qm.run_queue(process, 12)
    
    time.sleep(10)
    
    qm.remove_queue_rule("OUTPUT", "-p tcp --dport 4545", 12)
    print "after !"

    qm.stopall()