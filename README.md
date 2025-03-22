## Networks-2
PCAP programming and flow-level information with congestion control.

## High-level Summary of analysis_pcap_tcp.py
This code analyzes PCAP files to describe the TCP traffic from a sender to a receiver.
It outputs flow details such as connection, transactions, throughput, congestion window sizes, and retransmission statistics.
The code identifies TCP flows using a SYN packet, up until the last packet of that connection.
The 3-way handshake is considered complete for a TCP flow when the code encounters the final ack for the handshake.
After the handshake is complete, the code collects some transactional data from packets, including sequence number, ACK number, and received window size.
Actual window size is calculated using the formula: tcp.win << window_scale.
For throughput, the code counts all the bytes sent through a flow and the timestamps of the first and last packet (for calculating duration). Throughput is then calculated using the formula: bytes_sent / duration.
For estimating congestion window sizes, the code tracks sequence numbers and their timestamps for a flow. Whenever an ACK is sent, the code calculates the RTT between the ACK and the packet(s) it is acknowledging from the opposite end of the connection. This RTT is used to build a list, which the code takes the median of and uses that to collect the number of packets within RTT intervals, these are the congestion window sizes.
For retransmissions, the code considers an ACK sent more than once as a retransmission due to a triple-duplicate ACK. It also considers a sequence number sent more than once as a retransmission due to a timeout.

## Libraries used:
dpkt - for parsing PCAP data
socket - for converting inet objects into strings (for IP addresses)
collections.namedtuple - for creating a TCP connection 4-tuple data structure

## How to run:
1. Open command prompt.
2. Install the required dpkt library with "pip install dpkt".
3. The code is hardcoded to support a sender IP address of 130.245.145.12 and a receiver IP address of 128.208.2.198, change this as necessary by editing the constant variables at the top of the python code. You can also change the number of transactions and congestion window sizes to output. 
4. CD into the directory where analysis_pcap_tcp.py and the PCAP file to analyze is.
5. Run the analysis using "python analysis_pcap_tcp.py (pcap_file)" where (pcap_file) is the name of the PCAP file to analyze (ex: "python analysis_pcap_tcp.py assignment2.pcap").
