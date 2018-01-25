#this is to transform to bps
CONV_TABLE = {'k': 1000, 'm': 1000000, 'g': 1000000000}

#this dictionary controls the naming of attributes inside ES for main report
main_attribute = {
'Total incoming pps': 'total_incoming_pps', 
'Average incoming traffic': 'average_incoming_traffic', 
'Outgoing tcp traffic': 'outgoing_tcp_traffic', 
'Initial attack power': 'initial_attack_power', 
'Peak attack power': 'peak_attack_power', 
'Incoming ip fragmented traffic': 'incoming_ip_fragmented_traffic', 
'Total outgoing pps': 'total_outgoing_pps', 
'Average outgoing pps': 'average_outgoing_pps', 
'Attack type': 'attack_type', 
'Outgoing icmp traffic': 'outgoing_icmp_traffic', 
'Total incoming flows': 'total_incoming_flows', 
'Outgoing icmp pps': 'outgoing_icmp_pps', 
'Incoming udp pps': 'incoming_udp_pps', 
'Outgoing ip fragmented traffic': 'outgoing_ip_fragmented_traffic', 
'Average incoming pps': 'average_incoming_pps', 
'Outgoing ip fragmented pps': 'outgoing_ip_fragmented_pps', 
'Incoming udp traffic': 'incoming_udp_traffic', 
'Incoming syn tcp traffic': 'incoming_syn_tcp_traffic', 
'Total outgoing traffic': 'total_outgoing_traffic', 
'Outgoing syn tcp pps': 'outgoing_syn_tcp_pps', 
'Total incoming traffic': 'total_incoming_traffic', 
'IP': 'client_ip', 
'Outgoing tcp pps': 'outgoing_tcp_pps', 
'Outgoing udp traffic': 'outgoing_udp_traffic', 
'Outgoing syn tcp traffic': 'outgoing_syn_tcp_traffic', 
'Incoming tcp traffic': 'incoming_tcp_traffic', 
'Average incoming flows': 'average_incoming_flows', 
'Incoming ip fragmented pps': 'incoming_ip_fragmented_pps', 
'Average outgoing traffic': 'average_outgoing_traffic', 
'Incoming tcp pps': 'incoming_tcp_pps', 
'Incoming icmp traffic': 'incoming_icmp_traffic', 
'Incoming icmp pps': 'incoming_icmp_pps', 
'Average outgoing flows': 'average_outgoing_flows', 
'Attack direction': 'attack_direction', 
'Outgoing udp pps': 'outgoing_udp_pps', 
'Incoming syn tcp pps': 'incoming_syn_tcp_pps', 
'Total outgoing flows': 'total_outgoing_flows', 
'Attack protocol': 'attack_protocol'
}

#Naming for the traffic sample regex captured groups
trafic_sample = {
1: 'date', 
3: 'time', 
5: 'src_ip', 
6: 'src_port', 
7: 'dst_ip', 
8: 'dst_port', 
9: 'protocol', 
10: 'fragments', 
11: 'packets', 
12: 'size_in_bytes', 
13: 'ttl', 
14: 'sample_ratio'
}
