from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import csv

def get_raw(path):
    raw = open(path, encoding = "ISO-8859-1")
    lines = csv.reader(raw)
    data = []
    for line in lines:
        data.append(line)
    return data 

def get_all_packet_length(rawdata):
    length = []
    for row in rawdata:
        if (not row[5] == 'Frame Length'):
            length.append(int(row[5]))
    return length

def get_TCP_packet_length(rawdata):
    length = []
    for row in rawdata:
        if row[10] and ( row[10] != 'TCP') :
            length.append(int(row[5]))
    return length
    
def get_UDP_packet_length(rawdata):
    length = []
    for row in rawdata:
        if row[12] and ( row[12] != 'UDP') :
            length.append(int(row[5]))
    return length

def get_IP_packet_length(rawdata):
    length = []
    for row in rawdata:
        if ('IP' in row[13]) and (row[13] != 'Type'):
            length.append(int(row[5]))
    return length

def get_nonIP_packet_length(rawdata):
    length = []
    for row in rawdata:
        if(not ('IP' in row[13]) ) and (row[13] != 'Type'):
            length.append(int(row[5]))
    return length

def get_TCP_headerSize(rawdata):
    length = []
    for row in rawdata:
        if row[10] and (row[10] != 'TCP'):
            length.append(int(row[9]))
    return length

def get_IP_headerSize(rawdata):
    length = []
    for row in rawdata:
        if ('IP' in row[13]) and (row[13] != 'Type') and (not (',' in row[7])) and row[7] != '':
            length.append(int(row[7]))
    return length           
            
def get_UDP_headerSize(rawdata):
    length = []
    for row in rawdata:
        if row[12] and (row[12] != 'UDP'):
            if row[15]:
                size = int(row[14]) - int(row[16])
                length.append(size)
            else:
                length.append(8)            
    return length       

#TODO: Solve log 0 error
def plot_cdf(data, title, log=True):
    if log:
        data = np.log(data)
    plt.figure()
    plt.hist(data, density=True, histtype='stepfilled', cumulative=True, alpha=0.75, edgecolor = 'black')
    xlabel = 'Log {} Size (Byte)'.format(title)
    plt.xlabel(xlabel)
    plt.ylabel("Occurrence Probability")
    plt.yticks(np.linspace(0,1,11))
    plt.title('CDF of {}'.format(title))
    plt.grid(True)
    plt.savefig("./{}.png".format(title))

def reconstruct_flow(rawdata):
    TCP_flows = {}
    UDP_flows = {}
    for row in rawdata:
        if row[10] and ( row[10] != 'TCP'):
            # decide which key to go into
            current_address = row[2] + ":" + row[17] + "<->" + row[3] + ":" + row[18]
            reverse_address = row[3] + ":" + row[18] + "<->" + row[2] + ":" + row[17]
            if (current_address in TCP_flows.keys()) or (reverse_address in TCP_flows.keys()):
                if current_address in TCP_flows.keys():
                    TCP_flows[current_address].append(row)
                else:
                    TCP_flows[reverse_address].append(row)
            else:
                TCP_flows[current_address] = [row]


        elif row[12] and (row[12] != 'UDP'):
            # decide which key to go into
            current_address = row[2] + ":" + row[19] + "<->" + row[3] + ":" + row[20]
            reverse_address = row[3] + ":" + row[20] + "<->" + row[2] + ":" + row[19]
            if (current_address in UDP_flows.keys()) or (reverse_address in UDP_flows.keys()):
                if current_address in UDP_flows.keys():
                    UDP_flows[current_address].append(row)
                else:
                    UDP_flows[reverse_address].append(row)
            else:
                UDP_flows[current_address] = [row]      
    return TCP_flows, UDP_flows


def get_flow_type(flows):
    return len(flows)

def get_flow_duration(flows):
    durations = []
    for key in list(flows.keys()):
        times_for_a_flow = []
        for p in flows[key]:
            times_for_a_flow.append(float(p[1]))
        durations.append(max(times_for_a_flow) - min(times_for_a_flow))
    return durations

def get_flow_size(flows):
    flows_packet_count =[]
    flows_byte_count = []
    for key in list(flows.keys()):
        total = 0 
        flows_packet_count.append(len(flows[key]))
        for p in flows[key]:
            total += int(p[5])
        flows_byte_count.append(total)
    return flows_byte_count,flows_packet_count

def get_overhead_ratio(tcp_flows):
    for flow_index in list(tcp_flows.keys()):
        tcp_flow = tcp_flows[flow_index]
        list_tcp_flows = dict_to_list(tcp_flows)
        tcp_headers = get_TCP_headerSize(list_tcp_flows)
        ip_headers = get_IP_headerSize(list_tcp_flows)
        ethernet_headers = []
        for p in tcp_flow:
            # print(p)
            ethernet_headers.append(int(p[5])-int(p[8]))
        sum_headers = float(sum(tcp_headers) + sum(ip_headers) + sum(ethernet_headers))
        sum_sizes = float(sum(get_all_packet_length(list_tcp_flows)))
        return sum_headers/sum_sizes

def dict_to_list(dict):
    l = []
    for key in list(dict.keys()):
        l += dict[key]
    return l



def get_inter_packet_arrival_time(flows):
    inter_time = []
    one_direction = []
    another_direction = []
    for flow_index in list(flows.keys()):
        flow = flows[flow_index]
        standard_src = flow[0][2]
        standard_dst = flow[0][3]
        d1 = []
        d2 = []
        for p in flow:
            if standard_src == p[2]:
                d1.append(p)
            else:
                d2.append(p)
        one_direction.append(d1)
        another_direction.append(d2)
    for flow in one_direction:
        for i in range(1,len(flow)):
            inter_time.append(float(flow[i][1])-float(flow[i-1][1]))
            if float(flow[i][1])-float(flow[i-1][1]) > 45:
                print(flow[i])
    return inter_time

def get_tcp_state(tcp_flows):
    states = []
    keys = list(tcp_flows.keys())
    for flow_index in keys:
        flow = tcp_flows[flow_index]
        last_packet = flow[-1]
        if last_packet[21] == "Set": # SYN
            states.append("Request")
        elif last_packet[22] == "Set": # Reset
            states.append("Reset")
        elif len(flow) >= 4  and (flow[-4][2] == flow[-1][2]) and (flow[-3][2] == flow[-2][2]) and flow[-4][23] == "Set" and flow[-3][24] == "Set" and flow[-2][23] == "Set" and flow[-1][24] == "Set":
            states.append("Finished")
        else:
            states.append("Ongoing")
    return states.count("Request"), states.count("Reset"), states.count("Finished"), states.count("Ongoing")


def get_top_flows_packet_number(tcp_flows):

    top_three_flows = []
    temp = {}
    length = []
    flag = True
    for key in list(tcp_flows.keys()):
        flow = tcp_flows[key]
        length.append(len(flow))
    max1 = max(length)
    length.remove(max1)
    max2 = max(length)
    length.remove(max2)
    max3 = max(length)
    length.remove(max3)

    curr_f = []
    for key in list(tcp_flows.keys()):
        flow = tcp_flows[key]
        if (len(top_three_flows)<3) and (not flow in curr_f) and (len(flow) == max1 or len(flow) == max2 or len(flow)== max3):
            top_three_flows.append(flow)
            print("length of flow: " + str(len(flow)))
            curr_f.append(flow)
    print("max1: "+str(max1))
    print("max2: "+str(max2))
    print("max3: "+str(max3))
    return top_three_flows        



def get_top_flows_total_byte(tcp_flows):
    top_three_flows = []
    flow_pSize_list = []
    for key in list(tcp_flows.keys()):
        flow = tcp_flows[key]
        curr_flow_packet_size = 0
        for p in flow:
            curr_flow_packet_size += int(p[5])
        flow_pSize_list.append(curr_flow_packet_size)
    max1 = max(flow_pSize_list)
    flow_pSize_list.remove(max1)
    max2 = max(flow_pSize_list)
    flow_pSize_list.remove(max2)
    max3 = max(flow_pSize_list)
    flow_pSize_list.remove(max3)

    curr_f = []
    for key in list(tcp_flows.keys()):
        flow = tcp_flows[key]
        curr_flow_packet_size = 0
        for p in flow:
            curr_flow_packet_size += int(p[5])
        if (len(top_three_flows)<3) and (not flow in curr_f) and (curr_flow_packet_size == max1 or curr_flow_packet_size == max2 or curr_flow_packet_size== max3):
            top_three_flows.append(flow)
            print("Size of flow: " + str(curr_flow_packet_size))
            curr_f.append(flow)  
    print("max1: "+str(max1))
    print("max2: "+str(max2))
    print("max3: "+str(max3))
    print(len(top_three_flows))
    return top_three_flows                     


        

def get_top_flows_duration(tcp_flows):
    top_three_flows = []
    durations =  get_flow_duration(tcp_flows)
    max1 = max(durations)
    durations.remove(max1)
    max2 = max(durations)
    durations.remove(max2)
    max3 = max(durations)
    durations.remove(max3)

    curr_f = []
    for key in list(tcp_flows.keys()):
        times_for_a_flow = []
        flow = tcp_flows[key]
        for p in flow:
            times_for_a_flow.append(float(p[1]))
        duration = max(times_for_a_flow) - min(times_for_a_flow)
        if (len(top_three_flows)<3) and (not flow in curr_f) and (duration == max1 or duration == max2 or duration== max3):
            top_three_flows.append(flow)
            print("Size of flow: " + str(duration))
            curr_f.append(flow)  
    print("max1: "+str(max1))
    print("max2: "+str(max2))
    print("max3: "+str(max3))
    print(len(top_three_flows))
    return top_three_flows



def get_rtt(flow, direction):
    #type = packets, duration, bytes
    #number = 0, 1, 2
    #direction = 0,1
    # return:
    # estimates_rtt, real_rtt, time
    alpha = 0.125
    estimate_rtt = []
    real_rtt = []
    time = []
    # for flow in list_of_flows:
    if direction:
        std_src = flow[0][2] 
    else:
        std_src = flow[0][3]
    SRTT = 0
    for p in flow:
        if p[2]== std_src and p[26]:
            if not SRTT and float(p[26]):
                SRTT = float(p[26])
            real_rtt.append(float(p[26]))
            estimate_rtt.append((1-alpha) * SRTT + alpha * float(p[26]))
            SRTT = estimate_rtt[-1]
            time.append(float(p[1]))
    return [real_rtt, estimate_rtt, time]

def plot_RTT(real_rtt, estimate_rtt, time, title):
    # rows = plot_helper(all_real_RTT1, all_estimated_RTT1, all_time_RTT1)
    plt.figure(1)
    plt.plot(time,real_rtt,'g',marker='o',label='real_RTT_1')
    plt.plot(time,estimate_rtt,'b',marker='o',label='real_RTT_1')
    # plt.plot(all_time_RTT1,all_real_RTT1,'g',marker='o',label='real_RTT_1',markersize=1,linewidth=0.1)
    # plt.plot(rows[0][2],rows[0][0],'g',marker='o',label='real_RTT_1',markersize=1,linewidth=0.1)
    # plt.plot(rows[0][2],rows[0][1],'b',marker='o',label='estimated_RTT_1',markersize=1,linewidth=0.1)
    plt.title("RTT")
    plt.savefig(title+".png")


    # rows = plot_helper(all_real_RTT2, all_estimated_RTT2,all_time_RTT2)
    # for row in rows:
    #     plt.plot(row[2],row[0],'g',marker='o',label='real_RTT_2',markersize=1,linewidth=0.1)
    #     plt.plot(row[2],row[1],'b',marker='o',label='estimated_RTT_2',markersize=1,linewidth=0.1)

def get_top_tcp_same_hosts(tcpConnections):
    top_hosts = []
    hosts_packets = {}
    hosts_flows = []
    flow_number = []
    for row in tcpConnections:
        curr_key = row[2]+":"+row[3]
        reverse_key = row[3]+":"+row[2]
        if (curr_key in list(hosts_packets.keys())) or (reverse_key in list(hosts_packets.keys())):
            if(curr_key in list(hosts_packets.keys())):
                hosts_packets[curr_key].append(row)
            else:
                hosts_packets[reverse_key].append(row)
        else:
            hosts_packets[curr_key] = [row]
    for key in list(hosts_packets.keys()):
        packets = hosts_packets[key]
        TCP_flows,UDP_flows = reconstruct_flow(packets)
        hosts_flows.append(TCP_flows)
        flow_number.append(len(list(TCP_flows.keys())))
    max1 = max(flow_number)
    flow_number.remove(max1)
    max2 = max(flow_number)
    flow_number.remove(max2)
    max3 = max(flow_number)
    flow_number.remove(max3)  

    curr_f = []
    for host in hosts_flows:
        if (len(top_hosts)<3) and (not flow in curr_f) and (len(host) == max1 or len(host) == max2 or len(host)== max3):
            top_three_flows.append(host)
            curr_f.append(host)
    
    return top_hosts


if __name__ == '__main__':
    rawdata = get_raw('./raw4.csv')
    TCP_flows,UDP_flows = reconstruct_flow(rawdata)
    ALL_flows = {**TCP_flows, **UDP_flows}
    # print(get_overhead_ratio(TCP_flows))
    # print(TCP_flows[list(TCP_flows.keys())[0]])
    # print(UDP_flows[list(UDP_flows.keys())[0]])


    
    all_lengths = get_all_packet_length(rawdata)
    plot_cdf(all_lengths, "new All Packet Length")
    

    tcp_lengths = get_TCP_packet_length(rawdata)
    plot_cdf(tcp_lengths, "new TCP Packet Length")


    udp_lengths = get_UDP_packet_length(rawdata)
    plot_cdf(udp_lengths, "new UDP Packet Length")
    
    ip_packet_length = get_IP_packet_length(rawdata)
    plot_cdf(ip_packet_length, "new IP Packet Length")
    
    non_ip_packet_length = get_nonIP_packet_length(rawdata)
    plot_cdf(non_ip_packet_length, "new Non IP Packet Length")
    
    tcp_packet_header_size = get_TCP_headerSize(rawdata)
    plot_cdf(tcp_packet_header_size, "new TCP Packets Header Size")
    
    udp_packet_header_size = get_UDP_headerSize(rawdata)
    plot_cdf(udp_packet_header_size, "new UDP Packets Header Size")
    
    ip_packet_header_size = get_IP_headerSize(rawdata)
    print(ip_packet_header_size)
    plot_cdf(ip_packet_header_size, "new IP Packets Header Size")

    flow_duration = get_flow_duration(TCP_flows)
    plot_cdf(flow_duration, "TCP Flow Duration", False)

    tcp_flows_byte_count,tcp_flows_packet_count = get_flow_size(TCP_flows)
    plot_cdf(tcp_flows_packet_count, "TCP Flow Sizes By Count")
    plot_cdf(tcp_flows_byte_count, "TCP Flow Sizes By Byte")
    udp_flows_byte_count,udp_flows_packet_count = get_flow_size(UDP_flows)
    plot_cdf(udp_flows_packet_count, "UDP Flow Sizes By Count")
    plot_cdf(udp_flows_byte_count, "UDP Flow Sizes By Byte")
    all_flows_byte_count,all_flows_packet_count = get_flow_size(TCP_flows)
    plot_cdf(udp_flows_packet_count, "All Flow Sizes By Count")
    plot_cdf(all_flows_byte_count, "All Flow Sizes By Byte")

    tcp_inter_duration = get_inter_packet_arrival_time(TCP_flows)
    plot_cdf(tcp_inter_duration, "TCP Inter Packets Duration")

    udp_inter_duration = get_inter_packet_arrival_time(UDP_flows)
    plot_cdf(udp_inter_duration, "UDP Inter Packets Duration")

    all_duration = get_inter_packet_arrival_time(ALL_flows)
    plot_cdf(all_duration, "ALL Inter Packets Duration")

    print(get_tcp_state(TCP_flows))

    tcp_states = get_tcp_state(TCP_flows)
    print(tcp_states)

    packet1, packet2, packet3 = get_top_flows_packet_number(TCP_flows)
    duration1, duration2, duration3 = get_top_flows_duration(TCP_flows)
    byte1, byte2, byte3 = get_top_flows_total_byte(TCP_flows)
    picture_number = 1
    for flow in [packet1, packet2, packet3,duration1, duration2, duration3, byte1, byte2, byte3]:
        for direction in [0,1]:
            real_rtt, estimate_rtt, time = get_rtt(flow,direction)
            plot_RTT(real_rtt, estimate_rtt, time, "RTT_"+str(picture_number))
            picture_number +=1


    # count(tcp_states)
