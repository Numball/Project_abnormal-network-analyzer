import scapy.all as scapy
import matplotlib.pyplot as plt
import numpy as np




# Function to extract ICMP packet latencies from a pcap file
def extract_icmp_latency(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Initialize a list to store ICMP latencies
    icmp_latencies = []

    # Initialize the previous timestamp
    prev_timestamp = 0

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an ICMP layer
        if packet.haslayer(scapy.ICMP):
            # Get the timestamp of the current packet
            timestamp = packet.time
            # Calculate the latency if it's not the first packet
            if prev_timestamp != 0:
                latency = timestamp - prev_timestamp
                icmp_latencies.append(latency)
            # Update the previous timestamp for the next iteration
            prev_timestamp = timestamp

    # Return the list of ICMP latencies
    return icmp_latencies

# Function to extract UDP packet latencies from a pcap file
def extract_udp_latency(pcap_file):
    # Same logic as extract_icmp_latency, but for UDP packets
    packets = scapy.rdpcap(pcap_file)
    udp_latencies = []

    prev_timestamp = 0

    for packet in packets:
        if packet.haslayer(scapy.UDP):
            timestamp = packet.time
            if prev_timestamp != 0:
                latency = timestamp - prev_timestamp
                udp_latencies.append(latency)
            prev_timestamp = timestamp
    return udp_latencies

# Function to extract TCP packet latencies from a pcap file
def extract_TCP_latency(pcap_file):
    # Same logic as extract_icmp_latency, but for TCP packets
    packets = scapy.rdpcap(pcap_file)
    tcp_latencies = []

    prev_timestamp = 0

    for packet in packets:
        if packet.haslayer(scapy.TCP):
            timestamp = packet.time
            if prev_timestamp != 0:
                latency = timestamp - prev_timestamp
                tcp_latencies.append(latency)
            prev_timestamp = timestamp
    return tcp_latencies

# Function to plot latency comparisons for ICMP, TCP, and UDP packets
def plot_latency_comparison(normal_pcap, abnormal_pcap):
    # Extract ICMP latencies for normal and abnormal pcap files
    normal_ICMP_latencies = extract_icmp_latency(normal_pcap)
    abnormal_ICMP_latencies = extract_icmp_latency(abnormal_pcap)
    
    # Extract TCP latencies for normal and abnormal pcap files
    normal_TCP_latencies = extract_TCP_latency(normal_pcap)
    abnormal_TCP_latencies = extract_TCP_latency(abnormal_pcap)
    
    # Extract UDP latencies for normal and abnormal pcap files
    normal_UDP_latencies = extract_udp_latency(normal_pcap)
    abnormal_UDP_latencies = extract_udp_latency(abnormal_pcap)

    # Plot ICMP packet latencies
    plt.figure(figsize=(10, 6))
    plt.plot(normal_ICMP_latencies, label='Normal Traffic', color='blue')
    plt.plot(abnormal_ICMP_latencies, label='SMURF attack Traffic', color='red')
    plt.title('ICMP Packet Latency Comparison')
    plt.xlabel('Packet Number')
    plt.ylabel('Latency (seconds)')
    plt.legend()
    plt.grid()
    plt.show()

    # Plot TCP packet latencies
    plt.figure(figsize=(10, 6))
    plt.plot(normal_TCP_latencies, label='Normal Traffic', color='blue')
    plt.plot(abnormal_TCP_latencies, label='Abnormal Traffic', color='red')
    plt.title('TCP Packet Latency Comparison')
    plt.xlabel('Packet Number')
    plt.ylabel('Latency (seconds)')
    plt.legend()
    plt.grid()
    plt.show()

    # Plot UDP packet latencies
    plt.figure(figsize=(10, 6))
    plt.plot(normal_UDP_latencies, label='Normal Traffic', color='blue')
    plt.plot(abnormal_UDP_latencies, label='SMURF attack Traffic', color='red')
    plt.title('UDP Packet Latency Comparison')
    plt.xlabel('Packet Number')
    plt.ylabel('Latency (seconds)')
    plt.legend()
    plt.grid()
    plt.show()







# Function to extract ICMP packet latencies grouped by packet size
def extract_icmp_latency_by_packet_size(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Create a dictionary to store ICMP latencies by packet size
    icmp_latency_sizes = {}

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an ICMP layer
        if packet.haslayer(scapy.ICMP):
            # Get the size of the current packet
            packet_size = len(packet)
            # Get the timestamp of the current packet
            timestamp = packet.time
            # Check if the packet size already exists in the dictionary
            if packet_size in icmp_latency_sizes:
                # If it exists, append the timestamp to the list of latencies for that size
                icmp_latency_sizes[packet_size].append(timestamp)
            else:
                # If it doesn't exist, create a new entry with the size and initialize a list
                icmp_latency_sizes[packet_size] = [timestamp]

    # Return the dictionary of ICMP latencies grouped by packet size
    return icmp_latency_sizes

# Function to plot ICMP packet latencies vs packet size for normal and abnormal pcap files
def plot_latency_vs_packet_size(normal_pcap, abnormal_pcap):
    # Extract ICMP latencies grouped by packet size for normal and abnormal pcap files
    normal_latencies = extract_icmp_latency_by_packet_size(normal_pcap)
    abnormal_latencies = extract_icmp_latency_by_packet_size(abnormal_pcap)

    # Create a new plot
    plt.figure(figsize=(10, 6))

    # Plot normal packet latencies vs packet size
    for size, latencies in normal_latencies.items():
        plt.scatter([size] * len(latencies), latencies, label=f'Normal Size {size}', color='blue', s=5)

    # Plot abnormal packet latencies vs packet size
    for size, latencies in abnormal_latencies.items():
        plt.scatter([size] * len(latencies), latencies, label=f'Abnormal Size {size}', color='red', s=5)

    # Set the plot title, labels, legend, and grid
    plt.title('ICMP Packet Latency vs Packet Size')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Latency (milliseconds)')
    plt.legend()
    plt.grid()

    # Display the plot
    plt.show()






def analyze_conversations_ICMP(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    conversations = {}
    
    for packet in packets:
        if packet.haslayer('IP') and packet.haslayer('ICMP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            conversation_key = (src_ip, dst_ip)
            reverse_conversation_key = (dst_ip, src_ip)
            
            if conversation_key in conversations:
                conversations[conversation_key]['packets'] += 1
            elif reverse_conversation_key in conversations:
                conversations[reverse_conversation_key]['packets'] += 1
            else:
                conversations[conversation_key] = {
                    'packets': 1,
                }

    # Extract source and destination IPs for labels
    src_dst_ips = [f"{src_ip} -> {dst_ip}" for (src_ip, dst_ip) in conversations.keys()]
    packet_counts = [stats['packets'] for stats in conversations.values()]

    # Create a bar chart to show the number of packets exchanged
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(conversations)), packet_counts, tick_label=src_dst_ips)
    plt.xlabel('Conversation (Source IP -> Destination IP)')
    plt.ylabel('Number of Packets')
    plt.title('Conversations - Number of Packets Exchanged')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()




# Function to analyze conversations between source and destination IP addresses in a pcap file
def analyze_conversations(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Create a dictionary to store information about conversations
    conversations = {}
    
    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an 'IP' layer. Add "and pancket.haslayer('Protocol name') for protocol specific conversations"
        if packet.haslayer('IP'):
            # Extract source and destination IP addresses
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            # Create a conversation key as a tuple of (source IP, destination IP)
            conversation_key = (src_ip, dst_ip)
            # Create a reverse conversation key for bidirectional conversations
            reverse_conversation_key = (dst_ip, src_ip)
            
            # Check if the conversation key already exists in the 'conversations' dictionary
            if conversation_key in conversations:
                # If it exists, increment the packet count for that conversation
                conversations[conversation_key]['packets'] += 1
            # Check if the reverse conversation key exists
            elif reverse_conversation_key in conversations:
                # If it exists, increment the packet count for the reverse conversation
                conversations[reverse_conversation_key]['packets'] += 1
            else:
                # If the conversation is new, create an entry with packet count
                conversations[conversation_key] = {
                    'packets': 1,
                }

    # Extract source and destination IP addresses for labels
    src_dst_ips = [f"{src_ip} -> {dst_ip}" for (src_ip, dst_ip) in conversations.keys()]
    # Extract packet counts for each conversation
    packet_counts = [stats['packets'] for stats in conversations.values()]

    # Create a bar chart to show the number of packets exchanged in each conversation
    plt.figure(figsize=(12, 6))
    plt.bar(range(len(conversations)), packet_counts, tick_label=src_dst_ips)
    plt.xlabel('Conversation (Source IP -> Destination IP)')
    plt.ylabel('Number of Packets')
    plt.title('Conversations - Number of Packets Exchanged')
    plt.xticks(rotation=45, ha='right')  # Rotate and align the labels for better readability
    plt.tight_layout()  # Ensure the labels are not cut off in the plot
    plt.show()


    


def analyze_conversations_UDP(pcap_file):
        packets = scapy.rdpcap(pcap_file)
        conversations = {}
        
        for packet in packets:
            if packet.haslayer('IP') and packet.haslayer('UDP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                conversation_key = (src_ip, dst_ip)
                reverse_conversation_key = (dst_ip, src_ip)
                
                if conversation_key in conversations:
                    conversations[conversation_key]['packets'] += 1
                elif reverse_conversation_key in conversations:
                    conversations[reverse_conversation_key]['packets'] += 1
                else:
                    conversations[conversation_key] = {
                        'packets': 1,
                    }

        # Extract source and destination IPs for labels
        src_dst_ips = [f"{src_ip} -> {dst_ip}" for (src_ip, dst_ip) in conversations.keys()]
        packet_counts = [stats['packets'] for stats in conversations.values()]

        # Create a bar chart to show the number of packets exchanged
        plt.figure(figsize=(12, 6))
        plt.bar(range(len(conversations)), packet_counts, tick_label=src_dst_ips)
        plt.xlabel('Conversation (Source IP -> Destination IP)')
        plt.ylabel('Number of Packets')
        plt.title('Conversations - Number of Packets Exchanged')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()

    




# Function to calculate the throughput of a specific protocol in a pcap file
def calculate_protocol_throughput(pcap_file, protocol):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Filter packets that have the specified 'protocol' layer
    protocol_packets = [packet for packet in packets if packet.haslayer(protocol)]
    
    # Calculate the total bytes of the specified protocol in the pcap file
    total_protocol_bytes = sum(len(packet) for packet in protocol_packets)
    # Calculate the duration of the pcap capture
    pcap_duration = packets[-1].time - packets[0].time
    # Calculate the throughput in bits per second
    throughput = total_protocol_bytes / pcap_duration
    
    return throughput

# Function to plot a comparison of throughput for multiple protocols in normal and abnormal pcap files
def plot_protocol_throughput_comparison(normal_pcap, abnormal_pcap, protocols):
    # Calculate the throughput for each protocol in the normal and abnormal pcap files
    normal_throughputs = [calculate_protocol_throughput(normal_pcap, protocol) for protocol in protocols]
    abnormal_throughputs = [calculate_protocol_throughput(abnormal_pcap, protocol) for protocol in protocols]

    # Create a bar chart to compare the throughputs
    plt.figure(figsize=(10, 6))
    width = 0.35
    x = range(len(protocols))
    
    # Plot bars for normal and abnormal throughputs side by side
    plt.bar([i - width/2 for i in x], normal_throughputs, width, label='Normal Traffic', color='blue')
    plt.bar([i + width/2 for i in x], abnormal_throughputs, width, label='Abnormal Traffic', color='red')

    plt.xticks(x, protocols)  # Set protocol names as x-axis labels
    plt.title('Protocol Throughput Comparison')
    plt.xlabel('Protocol')
    plt.ylabel('Throughput (bits per second)')
    plt.legend()
    plt.grid()

    plt.show()






# Function to calculate the distribution of protocols in a pcap file
def calculate_protocol_distribution(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Create a dictionary to store the counts of different protocols
    protocols = {}
    
    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an 'IP' layer
        if packet.haslayer('IP'):
            # Extract the protocol number from the 'IP' layer
            protocol = packet['IP'].proto
            # If the protocol is not in the 'protocols' dictionary, add it with a count of 0
            if protocol not in protocols:
                protocols[protocol] = 0
            # Increment the count for the specific protocol
            protocols[protocol] += 1
    
    # Create a dictionary to map protocol numbers to their names
    protocol_names = {
        1: 'ICMP',
        2: 'IGMP',
        3: 'GGP',
        # ... (other protocol numbers and names)
        17: 'UDP',
        18: 'MUX',
        19: 'DCN-MEAS',
        20: 'HMP',
    }
    
    # Create labels for the pie chart based on protocol names
    labels = [protocol_names.get(key, 'Other') for key in protocols.keys()]
    # Create a list of sizes for each protocol count
    sizes = list(protocols.values())
    
    # Create a pie chart to visualize the protocol distribution
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures a circular pie chart
    plt.title('Protocol Distribution')
    plt.show()






# Function to calculate the Packet Transfer Ratio (PTR) for a pcap file
def calculate_ptr(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Calculate the total number of packets in the pcap file
    total_packets = len(packets)
    # Initialize a counter for successful packets
    successful_packets = 0

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an 'IP' layer (indicating a successful packet)
        if packet.haslayer(scapy.IP):
            successful_packets += 1

    # Calculate the Packet Transfer Ratio (PTR) as a percentage
    ptr = (successful_packets / total_packets) * 100
    return ptr

# Function to plot a comparison of PTR for two pcap files with labels
def plot_ptr_comparison(pcap_file1, pcap_file2, labels):
    # Calculate PTR for both pcap files
    ptr1 = calculate_ptr(pcap_file1)
    ptr2 = calculate_ptr(pcap_file2)

    # Create a bar chart to compare the PTR values with labels
    plt.figure(figsize=(8, 6))
    plt.bar(labels, [ptr1, ptr2], color=['blue', 'red'])
    plt.title('Packet Transfer Ratio (PTR) Comparison')
    plt.ylabel('PTR (%)')
    plt.grid()

    plt.show()








# Function to find the top talkers in a pcap file
def find_top_talkers(pcap_file, num_top_talkers=10):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Create a dictionary to store IP counts
    ip_counts = {}

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an 'IP' layer
        if packet.haslayer(scapy.IP):
            # Extract source and destination IP addresses
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # Update the count for the source IP
            if src_ip in ip_counts:
                ip_counts[src_ip] += 1
            else:
                ip_counts[src_ip] = 1

            # Update the count for the destination IP
            if dst_ip in ip_counts:
                ip_counts[dst_ip] += 1
            else:
                ip_counts[dst_ip] = 1

    # Find the top talkers based on IP counts
    top_talkers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:num_top_talkers]
    return top_talkers

# Function to plot a comparison of top talkers between two pcap files
def plot_top_talkers_comparison(pcap_file1, pcap_file2, num_top_talkers=10):
    # Find the top talkers for both pcap files
    top_talkers1 = find_top_talkers(pcap_file1, num_top_talkers)
    top_talkers2 = find_top_talkers(pcap_file2, num_top_talkers)

    # Separate top talker IPs and counts for each pcap file
    top_talker_ips1, top_talker_counts1 = zip(*top_talkers1)
    top_talker_ips2, top_talker_counts2 = zip(*top_talkers2)

    # Create a horizontal bar chart to compare top talkers
    fig, ax = plt.subplots(figsize=(10, 6))
    
    y_pos1 = range(len(top_talker_ips1))
    y_pos2 = [x + 0.4 for x in y_pos1]

    ax.barh(y_pos1, top_talker_counts1, label='Normal', color='blue', alpha=0.6, height=0.4)
    ax.barh(y_pos2, top_talker_counts2, label='Abnormal', color='red', alpha=0.6, height=0.4)

    ax.set_yticks([(y1 + y2) / 2 for y1, y2 in zip(y_pos1, y_pos2)])
    ax.set_yticklabels(top_talker_ips1)

    plt.title('Top Talkers Comparison')
    plt.xlabel('Packet Count')
    plt.ylabel('IP Address')
    plt.legend()
    plt.grid()

    plt.show()







# Function to plot throughput for different TTL values in TCP packets
def plot_throughput_tcp_ttl(normal_pcap_file, abnormal_pcap_file, ttl_values):
    # Initialize lists to store throughput data for normal and abnormal traffic
    normal_throughput = []
    abnormal_throughput = []

    # Loop through the normal and abnormal pcap files
    for pcap_file in [normal_pcap_file, abnormal_pcap_file]:
        # Read the pcap file and store packets in 'packets'
        packets = scapy.rdpcap(pcap_file)
        # Initialize a list of zeros for throughput, one element for each TTL value
        throughput = [0] * len(ttl_values)
        
        # Loop through each packet in the 'packets' list
        for packet in packets:
            # Check if the packet has 'IP' and 'TCP' layers
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                # Extract the TTL value from the 'IP' layer
                ttl = packet[scapy.IP].ttl
                # Check if the TTL value is in the provided 'ttl_values' list
                if ttl in ttl_values:
                    # Find the index of the TTL value in 'ttl_values'
                    index = ttl_values.index(ttl)
                    # Increment the throughput value at the corresponding index
                    throughput[index] += len(packet)
        
        # Store the throughput data in the appropriate list
        if pcap_file == normal_pcap_file:
            normal_throughput = throughput
        else:
            abnormal_throughput = throughput

    # Create a line plot to compare normal and abnormal traffic through TTL values
    plt.figure(figsize=(10, 6))
    plt.plot(ttl_values, normal_throughput, label='Normal Traffic', marker='o')
    plt.plot(ttl_values, abnormal_throughput, label='Abnormal Traffic', marker='x')
    plt.xlabel('TTL Values')
    plt.ylabel('Throughput (bits per second)')
    plt.title('Throughput Comparison for Different TTL Values')
    plt.legend()
    plt.grid(True)
    plt.xticks(ttl_values, ttl_values)
    plt.show()







# Function to plot the Time-to-Live (TTL) comparison between normal and abnormal traffic
def plot_ttl_comparison(normal_pcap_file, abnormal_pcap_file):
    # Initialize lists to store TTL values for normal and abnormal traffic
    normal_ttl_values = []
    abnormal_ttl_values = []

    # Read and process the normal traffic PCAP file
    normal_packets = scapy.rdpcap(normal_pcap_file)
    for packet in normal_packets:
        # Check if the packet has an 'IP' layer
        if scapy.IP in packet:
            # Extract and store the TTL value from the 'IP' layer
            normal_ttl_values.append(packet[scapy.IP].ttl)

    # Read and process the abnormal traffic PCAP file
    abnormal_packets = scapy.rdpcap(abnormal_pcap_file)
    for packet in abnormal_packets:
        # Check if the packet has an 'IP' layer
        if scapy.IP in packet:
            # Extract and store the TTL value from the 'IP' layer
            abnormal_ttl_values.append(packet[scapy.IP].ttl)

    # Create subplots for side-by-side histograms
    plt.figure(figsize=(12, 6))
    plt.subplot(1, 2, 1)  # Create the left subplot
    plt.hist(normal_ttl_values, bins=50, color='blue', alpha=0.7, label='Normal Traffic')
    plt.xlabel('TTL Value')
    plt.ylabel('Packet Count')
    plt.legend()

    plt.subplot(1, 2, 2)  # Create the right subplot
    plt.hist(abnormal_ttl_values, bins=50, color='red', alpha=0.7, label='Abnormal Traffic')
    plt.xlabel('TTL Value')
    plt.ylabel('Packet Count')
    plt.legend()

    plt.tight_layout()  # Ensure proper layout spacing
    plt.show()  # Display the subplots with histograms







# Function to calculate jitter values between packets in a pcap file
def calculate_jitter(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Initialize a list to store jitter values
    jitter_values = []
    previous_packet_time = None

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if we have a previous packet's timestamp
        if previous_packet_time is not None:
            # Calculate the jitter as the time difference between the current packet and the previous one
            jitter = packet.time - previous_packet_time
            jitter_values.append(jitter)
        previous_packet_time = packet.time

    return jitter_values

# Function to plot a comparison of jitter between normal and abnormal traffic
def plot_jitter_comparison(normal_pcap_file, abnormal_pcap_file):
    # Calculate jitter values for both normal and abnormal traffic
    normal_jitter = calculate_jitter(normal_pcap_file)
    abnormal_jitter = calculate_jitter(abnormal_pcap_file)

    # Create subplots for side-by-side jitter plots
    plt.figure(figsize=(12, 6))
    plt.subplot(1, 2, 1)  # Create the left subplot
    plt.plot(normal_jitter, color='blue', label='Normal Traffic')
    plt.xlabel('Packet Index')
    plt.ylabel('Jitter (seconds)')
    plt.legend()

    plt.subplot(1, 2, 2)  # Create the right subplot
    plt.plot(abnormal_jitter, color='red', label='Abnormal Traffic')
    plt.xlabel('Packet Index')
    plt.ylabel('Jitter (seconds)')
    plt.legend()

    plt.tight_layout()  # Ensure proper layout spacing
    plt.show()  # Display the subplots with jitter plots








# Function to count the number of packets for each protocol (TCP, UDP, ICMP) in a pcap file
def get_protocol_counts(pcap_file):
    # Initialize counters for TCP, UDP, and ICMP packets
    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    # Read and process packets from the pcap file
    packets = scapy.rdpcap(pcap_file)

    # Loop through each packet in the 'packets' list
    for packet in packets:
        # Check if the packet has an 'IP' layer
        if packet.haslayer(scapy.IP):
            # Check if the packet has a 'TCP' layer
            if packet.haslayer(scapy.TCP):
                tcp_count += 1
            # Check if the packet has a 'UDP' layer
            elif packet.haslayer(scapy.UDP):
                udp_count += 1
            # Check if the packet has an 'ICMP' layer
            elif packet.haslayer(scapy.ICMP):
                icmp_count += 1

    return tcp_count, udp_count, icmp_count

# Function to compare the protocol packet counts between normal and abnormal traffic
def compare_protocol_counts(normal_pcap_file, abnormal_pcap_file):
    # Get protocol counts for both normal and abnormal traffic
    normal_tcp, normal_udp, normal_icmp = get_protocol_counts(normal_pcap_file)
    abnormal_tcp, abnormal_udp, abnormal_icmp = get_protocol_counts(abnormal_pcap_file)
    
    # Define labels and counts for the bar chart
    labels = ['TCP', 'UDP', 'ICMP']
    normal_counts = [normal_tcp, normal_udp, normal_icmp]
    abnormal_counts = [abnormal_tcp, abnormal_udp, abnormal_icmp]

    x = range(len(labels))
    width = 0.35

    # Create a bar chart to compare protocol packet counts
    ax = plt.subplots()
    ax.bar(x, normal_counts, width, label='Normal Traffic')
    ax.bar([i + width for i in x], abnormal_counts, width, label='Abnormal Traffic')

    ax.set_xlabel('Protocols')
    ax.set_ylabel('Packet Count')
    ax.set_title('Protocol Packet Count Comparison')
    ax.set_xticks([i + width / 2 for i in x])
    ax.set_xticklabels(labels)
    ax.legend()

    plt.show()





# Function to calculate the throughput (in Kbps) for a given pcap file
def calculate_throughput(pcap_file):
    # Read the pcap file and store packets in 'packets'
    packets = scapy.rdpcap(pcap_file)
    # Get the start and end times of packet capture
    start_time = packets[0].time
    end_time = packets[-1].time
    # Calculate the total bytes transmitted in the pcap file
    total_bytes = sum(len(packet) for packet in packets)
    # Calculate the throughput in Kbps (kilobits per second)
    throughput = total_bytes / (end_time - start_time) / 1024
    return throughput

# Function to compare the throughput between normal and abnormal traffic
def compare_throughput(normal_pcap_file, abnormal_pcap_file):
    # Calculate throughput for both normal and abnormal traffic
    normal_throughput = calculate_throughput(normal_pcap_file)
    abnormal_throughput = calculate_throughput(abnormal_pcap_file)
    
    # Create a bar graph to compare throughput values
    labels = ['Normal Traffic', 'Abnormal Traffic']
    throughputs = [normal_throughput, abnormal_throughput]

    plt.bar(labels, throughputs)
    plt.xlabel('Traffic Type')
    plt.ylabel('Throughput (Kbps)')
    plt.title('Throughput Comparison')
    plt.show()








if __name__ == "__main__":
    normal_pcap_file = 'normal2.pcap'
    abnormal_pcap_file = 'abnormal.pcap'
    plot_latency_comparison(normal_pcap_file, abnormal_pcap_file)
    plot_latency_vs_packet_size(normal_pcap_file,abnormal_pcap_file)
    analyze_conversations_ICMP(normal_pcap_file)
    analyze_conversations_ICMP(abnormal_pcap_file)
    analyze_conversations(normal_pcap_file)
    analyze_conversations(abnormal_pcap_file)
    analyze_conversations_UDP(normal_pcap_file)
    analyze_conversations_UDP(abnormal_pcap_file)
    plot_protocol_throughput_comparison(normal_pcap_file,abnormal_pcap_file,[scapy.TCP,scapy.UDP,scapy.ICMP])
    calculate_protocol_distribution(normal_pcap_file)
    calculate_protocol_distribution(abnormal_pcap_file)
    plot_ptr_comparison(normal_pcap_file,abnormal_pcap_file,['Normal','Abnormal'])
    plot_top_talkers_comparison(normal_pcap_file,abnormal_pcap_file,5)
    plot_throughput_tcp_ttl(normal_pcap_file,abnormal_pcap_file,[51, 57, 64, 123, 239])
    plot_ttl_comparison(normal_pcap_file,abnormal_pcap_file)
    plot_jitter_comparison(normal_pcap_file, abnormal_pcap_file)
    compare_protocol_counts(normal_pcap_file,abnormal_pcap_file)
    compare_throughput(normal_pcap_file,abnormal_pcap_file)