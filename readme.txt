'''
CSC 361 Assignment 3
Author: Aaron Kao
---------------------
Purpose:
This program exists in order to analyze the trace of IP datagrams, giving data such 
as the intermediate nodes, RTT, fragment count, offset, and standard deviations.

Files:
a3.py
PartB.doc
readme.txt

Acknowledgements:
This assignment was completed as part of CSC 361 - Networks and Communications in Spring 2018 from the University of Victoria taught by Dr. Kui Wu.
The trace files provided as sample are also from Dr. Wu. Please note that the pcapng files have to be converted to .pcap before use. This can be done in WireShark.

Requirements:
Python 2.7 was used to construct this program. Python 3 will NOT work.

How to Run Program:

First off, the DPKT library needs to be installed. To install this library, enter pip install dpkt in the terminal

To run the program, only one parameter can be included. A command, such as the following is valid

python a3.py example.cap

Invalid commands include the following

python3 a3.py example.cap
python a3.py example.cap dolphins.cap

