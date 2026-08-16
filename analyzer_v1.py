from scapy.all import *

packets = rdpcap("Your_capture.pcapng") # rdpcap has creatred an array of elements of the capture file 

print("Number of Packets" , len(packets)) # as the packets is an array len counts the elements to give exact packet count

count = 0
scan_data = {} # empty dictionary for source ip key as well as destination ip with ports as values of each destination IP (A nested dictionary)

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

            if T_flags == "S": # we want our dictionary to hold IP source and the destination IP's with Respected ports associated with only the SYN flag

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

# adding the port summary to the end so it dosen't get repeated
print("\n===== SYN SCAN DETECTION SUMMARY =====")
for s_ip, destination in scan_data.items(): # access the first layer of the dictionary , scan_data = { "192.102.1.1" : {"100.2.1.2": { 22 , 20 , 80 } } }
    for d_ip, data in destination.items(): # access the 2nd layer "100.2.1.2": { 22 , 20 , 80 }
        ports = data["ports"]
        syn_c = data["syn_count"]

        p_len = len(ports)
        print(s_ip,"-->" ,d_ip, "on ports",ports)
        print("Unique ports: ",p_len)
        print("SYN FLAG COUNT : ",syn_c)
        if p_len>=10:
            print("⚠ Potential port scan detected!")
        elif p_len>=5:
            print("Suspicious activity detected!!!")
        else:
            print("No port-scan activity detected.")
