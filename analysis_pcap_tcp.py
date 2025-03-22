import dpkt # type: ignore
import socket
from collections import namedtuple

TCPConnection = namedtuple('TCPConnection', ['src_ip', 'src_port', 'dst_ip', 'dst_port']) # TCP 4-value tuple

# CONSTANTS
SENDER_IP = '130.245.145.12' # hardcoded address
RECEIVER_IP = '128.208.2.198' # hardcoded address
NUM_TRANSACTIONS_TO_OUTPUT = 2 # the number of transactions first after the three way handshake which should be output
NUM_CWNDS_TO_OUTPUT = 3 # the number of congestion window sizes to output

# Helper method to get median of a list, used for getting the median RTT of a stream.
def get_median(lst):
    sorted_lst = sorted(lst)
    n = len(sorted_lst)
    mid = n // 2
    if n % 2 == 0:
        return (sorted_lst[mid - 1] + sorted_lst[mid]) / 2
    else:
        return sorted_lst[mid]

# Extracts and prints TCP flow information from a PCAP file given a string of the file's path.
def analyze_pcap(pcap_file):

    streams = {} # tcp_connection -> flow. contains all half-streams (contains both flows sender->receiver and receiver->sender)
    
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, buf in pcap: # iterate through each frame in the pcap file
                try:
                    eth = dpkt.ethernet.Ethernet(buf) # get ethernet frame
                    if isinstance(eth.data, dpkt.ip.IP): # make sure it's an IP packet since we ignore non-TCP traffic
                        ip = eth.data # extract IP
                        if isinstance(ip.data, dpkt.tcp.TCP): # make sure the protocol is TCP since we ignore non-TCP traffic
                            tcp = ip.data # extract TCP

                            # extract 4-value tuple
                            tcp_connection = TCPConnection(
                                socket.inet_ntop(socket.AF_INET, ip.src), # convert inet object to string
                                tcp.sport,
                                socket.inet_ntop(socket.AF_INET, ip.dst), # convert inet object to string
                                tcp.dport
                            )
                            
                            # here we check if its a SYN packet and this stream has not already been established, 
                            # which would imply it is the start of a new TCP flow.
                            if (tcp.flags & dpkt.tcp.TH_SYN) and tcp_connection not in streams:
                                
                                # Look for window scale option in TCP options
                                window_scale = 0
                                for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
                                    if opt_type == 3:  # Window scale option (RFC 1323)
                                        if opt_data:
                                            # Window scale is the first byte of option data
                                            window_scale = ord(opt_data)
                                            break
                                
                                streams[tcp_connection] = {
                                    'start_time': timestamp,        # the timestamp of the first packet sent by this flow
                                    'end_time': timestamp,          # the timestamp of the last packet sent by this flow
                                    'bytes_sent': 0,                # the total number of bytes sent from this flow
                                    'handshake_complete': False,    # whether or not the 3-way handshake has been completed
                                    'num_transactions': 0,          # the number of transactions sent by this flow
                                    'output_transactions': [],      # the transactions to output
                                    'window_scale': window_scale,   # the window scale, for calculating window size
                                    'seen_seqs': [],                # sent sequence numbers by this flow
                                    'seen_acks': [],                # sent ack numbers by this flow
                                    'seen_times': [],               # sent timestamps by this flow
                                    'seqs_to_ack': {},              # sent sequence numbers that need to be acknowledged (seq -> timestamp)
                                    'rtts': [],                     # list of rtts in this flow
                                    'median_rtt': 0,                # the median RTT value, for estimation purposes
                                    'output_cwnds': [],             # the congestion window sizes to output
                                    'num_triple_duplicate_acks': 0, # the number of triple duplicate acks encountered by this flow
                                    'num_timeouts': 0,              # the number of timeouts encountered by this flow
                                }
                            
                            stream = streams[tcp_connection]

                            # Check for retransmission
                            if tcp.seq in stream['seen_seqs']:
                                if tcp.ack in stream['seen_acks']:
                                    stream['num_triple_duplicate_acks'] += 1
                                else:
                                    stream['num_timeouts'] += 1
                            
                            stream['seen_seqs'].append(tcp.seq)
                            stream['seqs_to_ack'][tcp.seq] = timestamp
                            stream['seen_acks'].append(tcp.ack)

                            # if we are acknowledging something, we need to calculate the RTT between the packets we are acking and when they were sent
                            if (tcp.flags & dpkt.tcp.TH_ACK):
                                opp_connection = TCPConnection(
                                    tcp_connection.dst_ip,
                                    tcp_connection.dst_port,
                                    tcp_connection.src_ip,
                                    tcp_connection.src_port
                                )
                                if opp_connection in streams:
                                    opp_stream = streams[opp_connection]
                                    seqs_to_ack = opp_stream['seqs_to_ack']
                                    ack = tcp.ack
                                    seqs_to_remove = []

                                    for seq, time_sent in seqs_to_ack.items():
                                        if seq < ack:
                                            rtt = timestamp - time_sent
                                            opp_stream['rtts'].append(rtt)
                                            seqs_to_remove.append(seq)

                                    for seq in seqs_to_remove:
                                        del opp_stream['seqs_to_ack'][seq]
                            
                            # collect bytes and transactions sent through this stream
                            stream['bytes_sent'] += len(tcp)
                            stream['num_transactions'] += 1
                            stream['end_time'] = timestamp # keep track of the most recent packet in this stream
                            stream['seen_times'].append(timestamp) # keep track of all timestamps (used for estimating congestion window sizes)

                            # collect the first few transactions after the handshake
                            if len(stream['output_transactions']) < NUM_TRANSACTIONS_TO_OUTPUT and stream['handshake_complete']:
                                stream['output_transactions'].append({
                                    'seq': tcp.seq,
                                    'ack': tcp.ack,
                                    'win': tcp.win << stream['window_scale'], # Calculate actual window size based on scaling factor
                                    'timestamp': timestamp
                                })
                            
                            # Check if its the third packet of the 3-way handshake (ACK)
                            if (tcp.flags & dpkt.tcp.TH_ACK) and not (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_FIN): # First check if its an ACK
                                if not stream['handshake_complete']: # Then check if the handshake has already been completed
                                    stream['handshake_complete'] = True
                        
                except Exception as e:
                    print(e)
                    continue # Skip this packet if an error occurs

            # Collect sender->receiver streams
            sen_to_rec_streams = {}
            for tcp_connection, flow in streams.items():
                if tcp_connection.src_ip == SENDER_IP and tcp_connection.dst_ip == RECEIVER_IP:
                    sen_to_rec_streams[tcp_connection] = flow

            # Estimate congestion window sizes at RTT intervals for every stream
            for tcp_connection, flow in sen_to_rec_streams.items():
                median_rtt = get_median(flow['rtts']) # get median RTT for this stream
                flow['median_rtt'] = median_rtt
                current_time = flow['start_time']
                end_time = flow['end_time']
                while current_time <= end_time and len(flow['output_cwnds']) < NUM_CWNDS_TO_OUTPUT:
                    num_pkts_in_interval = len([seq for seq, t in zip(flow['seen_seqs'], flow['seen_times']) # find the number of packets in this RTT interval
                                                if current_time <= t < current_time + median_rtt])
                    flow['output_cwnds'].append(num_pkts_in_interval) # add it to the congestion window sizes list
                    current_time += median_rtt

            # Print results
            print(f"Number of TCP flows initiated from the sender: {len(sen_to_rec_streams)}")
            print("\nFlow Details:")
            i = 1
            for tcp_connection, flow in sen_to_rec_streams.items():
                print(f"\nFlow {i}:")
                print(f"Source Port: {tcp_connection.src_port}, Source IP: {tcp_connection.src_ip}, "
                      f"Destination Port: {tcp_connection.dst_port}, Destination IP: {tcp_connection.dst_ip}")
                
                num_output_transactions = len(sen_to_rec_streams[tcp_connection]['output_transactions'])
                print(f"First {num_output_transactions} transactions after connection setup:")
                j = 1
                for transaction in sen_to_rec_streams[tcp_connection]['output_transactions']:
                    print(f"  Transaction {j}:")
                    print(f"    Sequence Number: {transaction['seq']}")
                    print(f"    ACK Number: {transaction['ack']}")
                    print(f"    Window Size: {transaction['win']} bytes")
                    j += 1

                bytes_sent = flow['bytes_sent']
                duration = flow['end_time'] - flow['start_time']
                throughput = bytes_sent / duration
                num_transactions = flow['num_transactions']
                print("Statistics:")
                print(f"  Bytes Sent: {bytes_sent} bytes ({(bytes_sent/1e6):.2f} MB)")
                print(f"  Duration: {duration:.4f} sec")
                print(f"  Throughput: {throughput:.2f} bytes/sec ({((bytes_sent/1e6)/duration):.2f} Mbps)")
                print(f"  Transactions: {num_transactions}")
                print(f"  Median RTT: {flow['median_rtt']:.2f} seconds")

                print(f"First {len(sen_to_rec_streams[tcp_connection]['output_cwnds'])} congestion window sizes:")
                j = 1
                for cwnd in sen_to_rec_streams[tcp_connection]['output_cwnds']:
                    print(f"  Window {j}: {cwnd} packets")
                    j += 1

                duplicate_acks = flow['num_triple_duplicate_acks'] - 1 # Ignore one duplicate ack, this was necessary for matching the analysis from Wireshark
                timeouts = flow['num_timeouts']
                print(f"Retransmissions: {duplicate_acks + timeouts}")
                print(f"  Due to triple duplicate acks: {duplicate_acks}")
                print(f"  Due to timeouts: {timeouts}")
                i += 1
        
    except FileNotFoundError:
        print(f"Error: File {pcap_file} not found.")
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python analysis_pcap_tcp.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)
