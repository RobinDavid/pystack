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

from netfilter.rule import Rule, Match
from netfilter.table import Table, IptablesError


def block_outgoing_packets(proto, ipsrc=None, portsrc=None, ipdst=None, portdst=None):
    """
    Blocks outgoing packets coming from the kernel using iptables command.
    """
    matches = []
    if portsrc:
        matches.append(Match('tcp', '--sport '+str(portsrc)))
    if portdst:
        matches.append(Match('tcp', '--dport '+str(portdst)))
    rule = Rule(
                #in_interface=interface,
                protocol=proto,
                source = ipsrc,
                destination = ipdst,
                matches=matches,
                jump='DROP')

    table = Table('filter')
    table.append_rule('OUTPUT', rule)

def unblock_outgoing_packets(proto, ipsrc=None, portsrc=None, ipdst=None, portdst=None):
    """
    Unblocks outgoing packets coming from the kernel using iptables command.
    """
    matches = []
    if portsrc:
        matches.append(Match('tcp', '--sport '+str(portsrc)))
    if portdst:
        matches.append(Match('tcp', '--dport '+str(portdst)))
    rule = Rule(
                #in_interface=interface,
                protocol=proto,
                source = ipsrc,
                destination = ipdst,
                matches=matches,
                jump='DROP')

    table = Table('filter')
    try:
        table.delete_rule('OUTPUT', rule)
    except IptablesError:
        print("Unknown rule !", proto, ipsrc, portsrc, ipdst, portdst)

def block_icmp_port_unreachable():
    """
    Blocks ICMP port unreachable packets sent by the kernel when a UDP port is hit without any service listening.
    """
    match =  Match('icmp', '--icmp-type port-unreachable')
    rule = Rule(protocol="icmp", matches=[match], jump='DROP')
    Table('filter').append_rule('OUTPUT', rule)

def unblock_icmp_port_unreachable():
    """
    Remove the rule that blocks ICMP port unreachable.
    """

    match =  Match('icmp', '--icmp-type port-unreachable')
    rule = Rule(protocol="icmp", matches=[match], jump='DROP')
    try:
        Table('filter').delete_rule('OUTPUT', rule)
    except IptablesError:
        print("Try to remove unexisting icmp port-unreachable")

if __name__ == "__main__":
    pass

'''
Other possible thing doable with netfilter module:
from netfilter.parser import parse_rule
table, rule = parse_rule("-A OUTPUT -p TCP -j DROP")


from netfilter import table
t = table.Table("filter")
t.list_chains() -> ['INPUT', 'FORWARD', 'OUTPUT']
t.list_rules("OUTPUT") -> #list of netfilter rules

Table -> filter
Chain -> Chain OUTPUT (policy ACCEPT)
         target     prot opt source               destination         
Rule ->  DROP       tcp  --  anywhere             linux-test1.local'''