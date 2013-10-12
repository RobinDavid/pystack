PyStack
=======

Pystack, is a python framework that allow to create small TCP/IP stacks in an easy manner in order to obtain a wanted behavior.
The applications are multiples and there is currently no any module that provide similar functionnalities in python.

It is developped above the Scapy framework to bring some network stateful functionalities adding to it multiple protocols implementations themselves architectured into a stack which allow the different layers to
communicate. All this **brings the IP stack in userland** and then allow to do anything on network packets like modifying the network stack behavior without patching the Linux kernel.

Full Documentation
==================

The full documentation with examples and explanation is available here: http://www.robindavid.comli.com/pystack

Package
=======

All the sources and examples are provided on Github. If you want only the module without documentation and example the module is available on Pypi : https://pypi.python.org/pypi/pystack

Installation
============

From pip:

    pip install pystack

From Github:

    git clone https://github.com/RobinDavid/pystack.git
    cd pystack
    python setup.py install 

Dependencies
------------

Pystack is currently relying on various libraries:

* Scapy (must)
* netfilter (must) (Will be removed soon for a hand made netfilter module)
* twisted (must) To make pystack work with reactor
* nfqueue (may) To use nfqueue functionalities
