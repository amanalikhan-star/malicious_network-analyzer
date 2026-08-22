from scapy.all import *

def get_severity(score):
    if score >= 50:
        return("CRITICAL")
    elif score >= 36 and score <=49:
        return("HIGH")
    elif score >= 10 and score <= 35:
        return("MEDIUM")
    elif score >= 7:
        return("NORMAL")
    else:
        return("NORMAL")

def detect_port_scan(scan_data):
    alerts = []
    print("\n===== SYN SCAN DETECTION SUMMARY =====")
    scan_count = 0
    for s_ip, destination in scan_data.items():
        

        destination_count = len(destination)
        print("\nSource IP:", s_ip)
        print("Unique destinations:", destination_count)

        for d_ip, data in destination.items():

            ports = data["ports"]
            syn_c = data["syn_count"]

            p_len = len(ports)
            severity = get_severity(p_len)

            print("\n", s_ip, "-->", d_ip)
            print("Ports:", ports)
            print("Unique ports:", p_len)
            print("SYN FLAG COUNT:", syn_c)

            if p_len >= 10:
                print("⚠ Potential port scan detected!")
                scan_count += 1
                alerts.append({ "source":s_ip,
                "destination": d_ip,
                "type": "Port-Scan",
                "unique_ports": p_len,
                "syn_count": syn_c,
                "Severity":severity })
            elif p_len >= 5:
                print("⚠ Suspicious activity detected!")
            else:
                print("No port-scan activity detected.")

    return alerts


def detect_host_scan(host_scan_data):
    hscan_alerts = []
    print("\n===== HOST SCAN SUMMARY =====")
    hscan_count = 0
    
    for s_ip, dest_data in host_scan_data.items():

        for port, destinations in dest_data.items():

            destination_count = len(destinations)
            severity = get_severity(destination_count)

            print(
                s_ip,
                "-->",
                port,
                "on",
                destination_count,
                "unique destinations"
                )
            if destination_count >= 10:
                print("Potential Horizontal scan detected!!!")
                hscan_alerts.append( { "source":s_ip,
                                     "ports": port,
                                     "destination_count": destination_count,
                                     "Type": "Horizontal Scan",
                                     "Severity": severity
                                     })
                hscan_count += 1
            elif destination_count >= 5:
                print("Suspicious activity detected!")
            else:
                print("Normal behaviour")
    return hscan_alerts

def analyze_tcp_flow(behaviour):
    syn = behaviour["syn"]
    syn_ack = behaviour["syn_ack"]
    ack = behaviour["ack"]
    rst = behaviour["rst"]

    if syn > 0 and syn_ack > 0 and ack > 0:
        return "COMPLETED"

    elif syn > 0 and rst > 0:
        return "REJECTED"

    elif syn > 0 and syn_ack == 0:
        return "INCOMPLETE"

    else:
        return "OTHER"
 

packets = rdpcap("port_scan.pcapng") # rdpcap has creatred an array of the capture file 

print("Number of Packets" , len(packets)) # as the packets is an array len counts the elements to give exact packet count

count = 0
scan_data = {} # empty dictionary for source ip key as well as destination ip with ports as values of each destination IP (A nested dictionary)
host_scan_data = {} # dictionary for source ip and ports which destination's were targeted  e.g host_scan_data = {"192.168.1.50": { 80: { "192.168.1.1","192.168.1.2", "192.168.1.3" }, 443: { "192.168.1.1","192.168.1.2" } } }
tcp_behaviour= {} # dictionary for monitering our flaqs associated with the tcp protocol

for packet in packets: # goes through whole list until break is used in the loop

    if packet.haslayer(IP): # check for IP header in the packet 
        source_ip = packet[IP].src # access source ip
        dest_ip = packet[IP].dst # access destination ip
        print("\n")
        print(" source IP: ",source_ip ,"\n", "destination IP: ",dest_ip) 

        if packet.haslayer(TCP): # checks for TCP header after ip layer ( eth->ip->TCP,UDP->app_data,data )
            source_port = packet[TCP].sport 
            destination_port = packet[TCP].dport
            T_flags = packet[TCP].flags  # accesses tcp flags 

            # TCP 4-tuple
            end_point1 = (source_ip,source_port)
            end_point2 = (dest_ip,destination_port)

            flow = tuple(sorted([end_point1,end_point2]))

            if flow not in tcp_behaviour:
                tcp_behaviour[flow] ={  # a tuple can be a key for a dictionary
                       "initiator": source_ip,
                        "initiator_port": source_port,
                        "responder": dest_ip,
                        "responder_port": destination_port,
                        "syn": 0,
                        "syn_ack": 0,
                        "ack": 0,
                        "rst": 0 }
                
            
            # OLD TCP BEHAVIOUR to track tcp concersation , in this for back to back handshakes the conections would be treated as different e.g 
            # Flow 1:
            # 192.168.1.50:51532 → 192.168.1.10:80
            # SYN = 1

            # Flow 2:
            # 192.168.1.10:80 → 192.168.1.50:51532
            # SYN-ACK = 1
            # these are part of the same connection
             # if source_ip not in tcp_behaviour:
            #     tcp_behaviour[source_ip] = {}
            # if dest_ip not in tcp_behaviour[source_ip]:
            #     tcp_behaviour[source_ip][dest_ip] = {}
            # if destination_port not in tcp_behaviour[source_ip][dest_ip]:
            #     tcp_behaviour[source_ip][dest_ip][destination_port] = {
            #         "syn": 0,
            #         "syn_ack": 0,
            #         "rst": 0,
            #         "ack": 0
            #     }
            if T_flags == "S":
                tcp_behaviour[flow]["syn"] += 1

            elif T_flags == "SA":
                tcp_behaviour[flow]["syn_ack"] += 1

            elif T_flags == "R":
                tcp_behaviour[flow]["rst"] += 1

            elif T_flags == "A":
                tcp_behaviour[flow]["ack"] += 1

            
            if T_flags == "S": # we want our dictionary to hold IP source and the destination IP's ,ports etc with Respected ports associated with only the SYN flag
                if source_ip not in host_scan_data:
                    host_scan_data[source_ip] = {}

                if destination_port not in host_scan_data[source_ip]:
                    host_scan_data[source_ip][destination_port] = set()

                host_scan_data[source_ip][destination_port].add(dest_ip)

                
                if source_ip not in scan_data: # we want to create a seperate dictionary for each SOURCE IP Inside the scan_data dictionary
                    scan_data[source_ip] = {}  # e.g scan_data = { "192.168.0.7": {} }

            
                if dest_ip not in scan_data[source_ip]:  # checking for respective source ip has unique destination IP's

                    scan_data[source_ip][dest_ip]={ "ports" : set() , "syn_count" : 0 } #  making sure each destination IP has a set for unique ports e.g  scan_data = { "192.168.0.7": {"192.168.0.10": set() , syn_count } } and now adding number of syn counts

                scan_data[source_ip][dest_ip]["ports"].add(destination_port) # adds ports to the set of the IP in the dictionary , associated with the syn flag
                scan_data[source_ip][dest_ip]["syn_count"] += 1

            print("TCP protocol")
            print("Source port: ", source_port )
            print("Destination port: ", destination_port )
            print("TCP flag: ", T_flags)
            if T_flags == "S":
                print("flag: SYN")
            elif T_flags == "A":
                print("flag: ACK")
            elif T_flags == "R":
                print("flag: RST")
            elif T_flags == "SA":
                print("flag: SYN + ACK")
            elif T_flags == "U":
                print("flag: URG")
            elif T_flags == "F":
                print("flag: FIN")
            elif T_flags == "FA":
                print("Flag: FIN + ACK")
            elif T_flags == "PA":
                print("Flag: PSH + ACK")
            else:
                print("other flag")

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print("UDP protocol")
            print("Source port: ",source_port )
            print("Destination port: ",destination_port )            

        elif packet.haslayer(ICMP):
            print("ICMP protocol")

        else:
            print("Other Protocol")

        count += 1

        # if(count>=30):
        #     break



port_scan_alerts = detect_port_scan(scan_data)

print("\n===== PORT SCAN ALERTS =====")
for p_d in port_scan_alerts:
    print("\n\tTotal Potential port scan data and count: ",p_d)

host_scan_alerts = detect_host_scan(host_scan_data)
print("\n===== HOST SCAN ALERTS =====")
for h_d in host_scan_alerts:
    print("\n\tTotal Potential Host scan data and count: ",h_d)

print("\n===== TCP FLOW SUMMARY =====")

for flow, behaviour in tcp_behaviour.items():
    print("\nFlow:", flow)
    print("SYN:", behaviour["syn"])
    print("SYN-ACK:", behaviour["syn_ack"])
    print("ACK:", behaviour["ack"])
    print("RST:", behaviour["rst"])

    status = analyze_tcp_flow(behaviour)

    print ("Status: ", status)
