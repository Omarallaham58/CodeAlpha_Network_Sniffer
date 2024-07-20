import socket
import string
import struct
import subprocess
import ipaddress
import argparse
import sys




def get_available_interfaces():
    result = subprocess.run(['./list_interfaces'], stdout=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        print("Error running the list_interfaces program.")
        exit(1)

    interfaces = []
    for line in result.stdout.splitlines():
        interfaces.extend(line.split())
    return interfaces


def enable_promiscuous_mode(interface):
    try:
        subprocess.run(['sudo', 'ifconfig', interface, 'promisc'], check=True)
        print("Promiscuous mode enabled on interface {}".format(interface))
    except subprocess.CalledProcessError as e:
        print("Error enabling promiscuous mode: {}".format(e))


def get_ethernet_frame(data):
    dest, src, type_or_len = struct.unpack('!6s6sH', data[:14])
    return format_mac(dest), format_mac(src), type_or_len, data[14:]
   


def format_mac(addr):
    # Convert bytes to hex string and insert colons
    hex_str = addr.hex()
    return ':'.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))


def decodeIpv4(header):
    version = header[0]
    header_length = int(header[1]) * 4  # length in 32 bits word (4 bytes) => multiply it by 4
    type_of_service = "" + header[2] + "" + header[3]
    total_length = int(header[4:8], 16)
    identification_hex = header[8:12]
    seventh_byte = int(header[12:14], 16)

    # Apply bitwise AND with a mask to isolate the 3-bit flag (assuming flag is in the most significant 3 bits)
    flag = (seventh_byte & 0xE0) >> 5
    flag_bin = format(flag, '03b')
    offset_bytes = int(header[12:16], 16)
    offset = (offset_bytes & 0x0FFF) * 8  # offset in 64 bits word
    offset_bin = format(offset, '013b')
    ttl = int(header[16:18], 16)
    protocol_num = int(header[18:20], 16)
    protocol = ""

    if protocol_num == 6:
        protocol = "TCP"
    elif protocol_num == 1:
        protocol = "ICMP"
    elif protocol_num == 0:
        protocol = "IP"
    elif protocol_num == 17:
        protocol = "UDP"
    elif protocol_num == 21:
        protocol = "IPv6 encapsulation (IPv6-in-IPv4)"
    else:
        protocol = "Unknown"

    checksum = header[20:24]

    src_ip = ("" + str(int(header[24:26], 16)) + "." + str(int(header[26:28], 16)) + "."
              + str(int(header[28:30], 16)) + "." + str(int(header[30:32], 16)))

    dest_ip = ("" + str(int(header[32:34], 16)) + "." + str(int(header[34:36], 16)) + "."
               + str(int(header[36:38], 16)) + "." + str(int(header[38:40], 16)))

    optional_data = "Not Available"

    if header_length * 2 > 40:
        optional_data = header[40:2 * header_length]
    return {
        "version": version,
        "header_length": header_length,
        "type_of_service": type_of_service,
        "total_length": total_length,
        "identification_hex": identification_hex,
        "flag_bin": flag_bin,
        "offset_bin": offset_bin,
        "offset": offset,
        "ttl": ttl,
        "protocol_num": protocol_num,
        "protocol": protocol,
        "checksum": checksum,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "optional_data": optional_data

    }


def decodeIpv6(header):
    version = header[0]
    traffic_class = header[1:3]
    flow_label = header[3:8]
    payload_length = int(header[8:12], 16)
    next_header_num = int(header[12:14], 16)
    next_header = ""

    if next_header_num == 6:
        next_header = "TCP"
    elif next_header_num == 1:
        next_header = "ICMP"
    elif next_header_num == 0:
        next_header = "IP"
    elif next_header_num == 17:
        next_header = "UDP"
    elif next_header_num == 21:
        next_header = "IPV6 Encapsulation (IPV6 - in - IPV4) "
    elif next_header_num == 58:
        next_header = "ICMPV6"
    else:
        next_header = "Unknown"

    hop_limit = int(header[14:16], 16)

    src_ip = ("" + header[16:20] + ":" + header[20:24] + ":" + header[24:28] + ":" + header[28:32] + ":" + header[
                                                                                                           32:36] + ":"
              + header[36:40] + ":" + header[40:44] + ":" + header[44:48])

    dest_ip = ("" + header[48:52] + ":" + header[52:56] + ":" + header[56:60] + ":" + header[60:64] + ":" + header[
                                                                                                            64:68] + ":"
               + header[68:72] + ":" + header[72:76] + ":" + header[76:80])

    return {
        "version": version,
        "traffic_class": traffic_class,
        "flow_label": flow_label,
        "payload_length": payload_length,
        "next_header_num": next_header_num,
        "next_header": next_header,
        "hop_limit": hop_limit,
        "src_ip": (ipaddress.IPv6Address(src_ip)).compressed,
        "dest_ip": (ipaddress.IPv6Address(dest_ip)).compressed
    }


def decodeIcmpv4(header):
    type = int(header[0:2], 16)
    code = int(header[2:4], 16)
    details = ""

    if type == 0:
        details = "Echo reply"

    elif type == 3:
        if code == 0:
            details = "Destination network unreachable"
        elif code == 1:
            details = "Destination host unreachable"
        elif code == 2:
            details = "Destination protocol unreachable"
        elif code == 3:
            details = "Destination port unreachable"
        elif code == 4:
            details = "Fragmentation is needed and the DF flag set"
        elif code == 5:
            details = "Source route failed"
    elif type == 5:
        if code == 0:
            details = "Redirect the datagram for the network"
        elif code == 1:
            details = "Redirect datagram for the host"
        elif code == 2:
            details = "Redirect the datagram for the Type of Service and Network"
        elif code == 3:
            details = "Redirect datagram from the Service & Host"
    elif type == 8:
        details = "Echo request"
    elif type == 9 or type == 10:
        details = "Operational Routers Addresses Discovery"
    elif type == 11:
        if code == 0:
            details = "TTL exceeded in transit"
        elif code == 1:
            details = "Fragment reassembly time exceeded"
    elif type == 12:
        if code == 0:
            details = "The pointer indicates an error"
        elif code == 1:
            details = "Missing required option"
        elif code == 2:
            details = "Bad length"
    elif type == 13:
        details = "Time Synchronization"
    elif type == 14:
        details = "Reply to timestamp message"

    checksum = header[4:8]
    extended_header = header[8:16]
    data = header[16:]
    # ascii_data = (bytes.fromhex(data)).decode('ascii')
    # Decode the data using 'latin1' to avoid UnicodeDecodeError
    try:
        ascii_data = bytes.fromhex(data).decode('latin1')
    except UnicodeDecodeError:
        ascii_data = "Non-ASCII data"

    return {
        "type": type,
        "code": code,
        "details": details,
        "checksum": checksum,
        "extended_header": extended_header,
        "data": data,
        "ascii_data": ascii_data
    }


def decodeIcmpv6(header):
    type = int(header[0:2], 16)
    code = int(header[2:4], 16)
    checksum = header[4:8]
    content = header[8:]
    details = ""

    if type == 0:
        details = "Destination unreachable: "
        if code == 0:
            details += "No route to destination"
        elif code == 1:
            details += "Communication with destination administratively prohibited"
        elif code == 2:
            details += "Beyond scope of source address"
        elif code == 3:
            details += "Address unreachable"
        elif code == 4:
            details += "Port unreachable"
        elif code == 5:
            details += "Source address failed ingress/egress policy"
        elif code == 6:
            details += "Reject route to destination"
        elif code == 7:
            details += "Error in source routing header"
    elif type == 2:
        details = "Packet too big"
    elif type == 3:
        details = "Time exceeded: "
        if code == 0:
            details += "Hop limit exceeded transit"
        elif code == 1:
            details += "Fragment reassembly time exceeded"
    elif type == 4:
        details = "Parameter problem"
        if code == 0:
            details += "Erroneous header field encountered "
        elif code == 1:
            details += "Unrecognized Next Header type encountered"
        elif code == 2:
            details += "Unrecognized IPv6 option encountered"
    elif type == 100 or type == 101:
        details = "Private experimentation"
    elif type == 127:
        details = "Research for expansion of ICMPV6 error messages"
    elif type == 128:
        details = "Echo Request"
    elif type == 129:
        details = "Echo Reply"
    elif type == 130:
        details = "Multicast Listener Query (MLD)"
    elif type == 131:
        details = "Multicast Listener Report (MLD)"
    elif type == 132:
        details = "Multicast Listener Done (MLD)"
    elif type == 133:
        details = "Router Solicitation (NDP)"
    elif type == 134:
        details = "Router Advertisement (NDP)"
    elif type == 135:
        details = "Neighbour Solicitation (NDP) "
    elif type == 136:
        details = "Neighbour Advertisement (NDP)"
    elif type == 137:
        details = "Redirect Message (NDP)"

    return {
        "type": type,
        "code": code,
        "checksum": checksum,
        "content": content,
        "details": details
    }


def decodeUdp(header):
    src_port = int(header[0:4], 16)
    dest_port = int(header[4:8], 16)
    length = int(header[8:12], 16)
    checksum = header[12:16]
    payload = header[16:]
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
        "checksum": checksum,
        "payload": payload
    }


def decodeTcp(header):
    src_port = int(header[0:4], 16)
    dest_port = int(header[4:8], 16)
    sequence_num = int(header[8:16], 16)
    ack_num = int(header[16:24], 16)
    data_offset_bin = (bin(int(header[24], 16)))[2:]
    data_offset = int(header[24], 16) * 4  # in 32 bit words (ie 4 bytes)
    reserved = str((bin(int(header[25], 16)))[2:].zfill(4))
    # flag_byte_bit = str((bin(int(header[26:28], 16))))[2:]
    flag_byte_bit = str((bin(int(header[26], 16)))[2:].zfill(4)) + str((bin(int(header[27], 16)))[2:].zfill(4))
    window_size = int(header[28:32], 16)
    checksum = header[32:36]
    urg = int(header[36:40], 16)
    payload = header[40:]
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence_num": sequence_num,
        "ack_num": ack_num,
        "header_length_bin": data_offset_bin,
        "header_length_bytes": data_offset,
        "reserved": reserved,
        "flag_byte_bits": flag_byte_bit,
        "window_size": window_size,
        "checksum": checksum,
        "urg": urg,
        "payload": payload
    }


def decodeArp(header):
    hwtype = int(header[0:4], 16)
    hardware_type = ""
    if hwtype == 1:
        hardware_type = "Ethernet (1)"
    elif hwtype == 6:
        hardware_type = "IEEE 802 (6)"
    elif hwtype == 7:
        hardware_type = "ARCNET (7)"
    elif hwtype == 15:
        hardware_type = "Frame Relay (15)"
    elif hwtype == 16 or hwtype == 19:
        hardware_type = "ATM"
    elif hwtype == 17:
        hardware_type = "HDLC (17)"
    elif hwtype == 18:
        hardware_type = "Fibre Channel (18)"
    elif hwtype == 20:
        hardware_type = "Serial Line (20)"
    else:
        hardware_type = "Unknown"
    proto = header[4:8]
    protocol_type = ""
    if proto == "0800":
        protocol_type = "0x0800 (IPv4)"
    elif proto == "0806":
        protocol_type = "0x0806 (ARP)"
    elif proto.lower() == "86dd":
        protocol_type = "0x86DD (IPv6)"
    elif proto == "0805":
        protocol_type = "0x0805 (XNS)"
    elif proto == "8137":
        protocol_type = "0x8137 (Novell IPX)"
    elif proto.lower() == "f0f0":
        protocol_type = "0xF0F0 (Apple Talk)"
    else:
        protocol_type = "Unknown"

    hardware_size = int(header[8:10], 16)
    protocol_size = int(header[10:12], 16)
    opcode = ""
    op = int(header[12:16], 16)
    if op == 1:
        opcode = "Request (1)"
    elif op == 2:
        opcode = "Reply (2)"
    else:
        opcode = op
    sender_mac = (':'.join(header[i:i+2] for i in range(16,28,2)))
    #sender_mac = format_mac(header[16:28])
    sender_ip = ("" + str(int(header[28:30], 16)) + "." + str(int(header[30:32], 16)) + "."
                 + str(int(header[32:34], 16)) + "." + str(int(header[34:36], 16)))
    target_mac = (':'.join(header[i:i+2] for i in range(36,48,2)))
    #target_mac = format_mac(header[36:48])
    target_ip = ("" + str(int(header[48:50], 16)) + "." + str(int(header[50:52], 16)) + "."
                 + str(int(header[52:54], 16)) + "." + str(int(header[54:56], 16)))

    return {
        "hardware_type": hardware_type,
        "protocol_type": protocol_type,
        "hardware_size": hardware_size,
        "protocol_size": protocol_size,
        "opcode": opcode,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip
    }


def main():
    # Create a raw socket and bind it to the network interface
    global decoded_ip, ip_header, decoded_arp
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    parser = argparse.ArgumentParser(description="Check if a network interface is available.")
    parser.add_argument("interface", help="The name of the network interface to check.")
    args = parser.parse_args()

    available_interfaces = get_available_interfaces()
    #print(type(available_interfaces))
    #print(available_interfaces)
    if args.interface in available_interfaces:
        print("Interface {} is available.".format(args.interface))
        # Place your sniffer code here
    else:
        print("Interface {} is not available.".format(args.interface))
        print("Available interfaces are:")
        for iface in available_interfaces:
            print(iface)
        exit(1)
    
    enable_promiscuous_mode(args.interface)
    try:
        while True:
            # Receive data from the socket
            #ip_header=[]
            raw_data, addr = conn.recvfrom(65535)
            # print("SIZE OF WHOLE DATA : {}".format(len(raw_data)))
            dest_mac, src_mac, eth_type_or_len, payload = get_ethernet_frame(raw_data)

            if eth_type_or_len == 0x0800:  # ipv4
                type_or_len = "0x0800 (IPV4)"
                ip_header = payload[:20].hex()
                decoded_ip = decodeIpv4(ip_header)

            elif eth_type_or_len == 0x86DD:  #ipv6
                type_or_len = "0x86DD (IPV6)"
                ip_header = payload[:40].hex()
                decoded_ip = decodeIpv6(ip_header)

            elif eth_type_or_len == 0x0806:
                type_or_len = "0x0800 (ARP)"
                decoded_arp = decodeArp(payload.hex())

            elif eth_type_or_len == 0x0842:
                type_or_len = "0x0842 (Wake-on-LAN)"

            elif eth_type_or_len == 0x8100:
                type_or_len = "0x8100 (VLAN Tagged Frame)"

            elif eth_type_or_len == 0x88cc:
                type_or_len = "0x8cc (Link Layer Discovery Protocol)"

            elif eth_type_or_len == 0x88e5:
                type_or_len = "0x88e5 (MAC Security)"

            else:
                type_or_len = "0x" + str(format(eth_type_or_len, '04x')) + " (non IP)"
            # type_or_len = "0x" + str(bytes(eth_type_or_len).hex()) + " (non IP)"

            print("--------------------------------------------------------------------")
            print("*************************\nEthernet Frame: {}".format(raw_data[:14].hex()))
            print("Source MAC Address: {} \t Destination MAC Address: {}\t Type/Len: {}".format(src_mac, dest_mac,
                                                                                                type_or_len))
            print("*************************")
            # print("DATA: {}".format(payload))
            if eth_type_or_len == 0x0800:  #ipv4
                print("IP Header: {}".format(ip_header))
                print("Version: {} ".format(decoded_ip["version"]))
                print("Header Length : {} Bytes".format(decoded_ip["header_length"]))
                print("Differentiated service field: 0x{}".format(decoded_ip["type_of_service"]))
                print("Total Length: {}".format(decoded_ip["total_length"]))
                print("Identification : 0x{} ({})".format(decoded_ip["identification_hex"],
                                                          int(decoded_ip["identification_hex"], 16)))
                print("FLAG bits: {}".format(decoded_ip["flag_bin"]))
                print("Fragment Offset : {} <=> {} ".format(decoded_ip["offset_bin"], decoded_ip["offset"]))
                print("Time To Live: {}".format(decoded_ip["ttl"]))
                print("Protocol: {} ({})".format(decoded_ip["protocol"], decoded_ip["protocol_num"]))
                print("Checksum: 0x{}".format(decoded_ip["checksum"]))
                print("Source Address: {}".format(decoded_ip["src_ip"]))
                print("Destination Address: {}".format(decoded_ip["dest_ip"]))
                print("Possible Options: {}".format(decoded_ip["optional_data"]))

                if decoded_ip["protocol_num"] == 1:  # icmp
                    icmp_header = payload[20:].hex()
                    decoded_icmp = decodeIcmpv4(icmp_header)
                    print("*************************")
                    print("ICMP Header Details:")
                    print("Type: {}\t Code: {}\t Details: {}".format(decoded_icmp["type"], decoded_icmp["code"],
                                                                     decoded_icmp["details"]))
                    print("Checksum: 0x{}".format(decoded_icmp["checksum"]))
                    print("Extended Header: {}".format(decoded_icmp["extended_header"]))
                    print("Data: {}\nData in ASCII: {}".format(decoded_icmp["data"], decoded_icmp["ascii_data"]))

            elif eth_type_or_len == 0x86dd:  #ipv6
                print("IP  Header: {} ".format(ip_header))
                #print("WHOLE DATA( size {} bytes): {}".format(len(payload) / 2, payload.hex()))
                print("Version: {}".format(decoded_ip["version"]))
                print("Traffic Class: 0x{}".format(decoded_ip["traffic_class"]))
                print("Flow Label: 0x{}".format(decoded_ip["flow_label"]))
                print("Payload Length: {}".format(decoded_ip["payload_length"]))
                print("Next Header: {} ({})".format(decoded_ip["next_header"], decoded_ip["next_header_num"]))
                print("Hop Limit: {}".format(decoded_ip["hop_limit"]))
                print("Source Address: {}".format(decoded_ip["src_ip"]))
                print("Destination Address: {}".format(decoded_ip["dest_ip"]))

                if decoded_ip["next_header_num"] == 58:  #icmpv6
                    decoded_icmp = decodeIcmpv6(payload[40:].hex())
                    print("*************************")
                    print("ICMPV6 Header Details:")
                    print("Type: {}\t Code: {}\t Description: {}".format(decoded_icmp["type"],
                                                                         decoded_icmp["code"], decoded_icmp["details"]))
                    print("Checksum: 0x{}".format(decoded_icmp["checksum"]))
                    print("Content: {}".format(decoded_icmp["content"]))

            elif eth_type_or_len == 0x0806:  # arp
                print("*************************")
                print("ARP Header: {}".format(payload.hex()))
                print("Hardware Type: {}\tProtocol Type: {}".format(decoded_arp["hardware_type"],
                                                                    decoded_arp["protocol_type"]))
                print("Hardware Size: {}\tProtocol Size: {}\tOpcode: {}".format(decoded_arp["hardware_size"],
                                                                                decoded_arp["protocol_size"],
                                                                                decoded_arp["opcode"]))
                print("Sender MAC Address: {}\tSender IP Address: {}".format(decoded_arp["sender_mac"],
                                                                             decoded_arp["sender_ip"]))
                print("Target MAC Address: {}\tTarget IP Address: {}".format(decoded_arp["target_mac"],
                                                                             decoded_arp["target_ip"]))



            else:
                print("*************************")
                print("Header: {}".format(payload.hex()))

            if (eth_type_or_len == 0x0800 and decoded_ip["protocol_num"] == 17) or (
                    eth_type_or_len == 0x86DD and decoded_ip["next_header_num"] == 17):
                udp_header = payload[20:].hex() if eth_type_or_len == 0x0800 else payload[40:].hex()
                decoded_udp = decodeUdp(udp_header)
                print("*************************")
                print("UDP Header: {} ".format(udp_header))
                print("Source Port: {}\t Destination Port: {}\t Length: {}".format(decoded_udp["src_port"],
                                                                                   decoded_udp["dest_port"],
                                                                                   decoded_udp["length"]))
                print("Checksum: 0x{}".format(decoded_udp["checksum"]))
                print("UDP Payload: {}".format(decoded_udp["payload"]))

            elif (eth_type_or_len == 0x0800 and decoded_ip["protocol_num"] == 6) or (
                    eth_type_or_len == 0x86DD and decoded_ip["next_header_num"] == 6):
                tcp_header = payload[20:].hex() if eth_type_or_len == 0x0800 else payload[40:].hex()
                decoded_tcp = decodeTcp(tcp_header)
                print("*************************")
                print("TCP Header: {} ".format(tcp_header))
                print(
                    "Source Port: {}\t Destination Port: {}".format(decoded_tcp["src_port"], decoded_tcp["dest_port"]))
                print("Sequence Number: {}\tAcknowledgement number: {}".format(decoded_tcp["sequence_num"],
                                                                               decoded_tcp["ack_num"]))
                print("Header Length : {} <=> {} Bytes".format(decoded_tcp["header_length_bin"],
                                                               decoded_tcp["header_length_bytes"]))
                print("Reserved: {}".format(decoded_tcp["reserved"]))
                print("Flag Bits: {}".format(decoded_tcp["flag_byte_bits"]))
                print("{}... .... => Congestion Window Reduced Flag (CWR)".format(decoded_tcp["flag_byte_bits"][0]))
                print(".{}.. .... => ECN Echo Flag".format(decoded_tcp["flag_byte_bits"][1]))
                print("..{}. .... => Urgent Pointer Flag (URG)".format(decoded_tcp["flag_byte_bits"][2]))
                print("...{} .... => Acknowledgement Flag (ACK)".format(decoded_tcp["flag_byte_bits"][3]))
                print(".... {}... => Push Flag (PSH)".format(decoded_tcp["flag_byte_bits"][4]))
                print(".... .{}.. => Reset Connection Flag (RST)".format(decoded_tcp["flag_byte_bits"][5]))
                print(".... ..{}. => Synchronize sequence number flag (SYN)".format(decoded_tcp["flag_byte_bits"][6]))
                print(".... ...{} => Last packet from sender (finish the connection) (FIN)".format(
                    decoded_tcp["flag_byte_bits"][7]))
                print("Window Size: {}".format(decoded_tcp["window_size"]))
                print("Checksum: 0x{}".format(decoded_tcp["checksum"]))
                print("Urgent Pointer: {}".format(decoded_tcp["urg"]))
                print("TCP Payload: {}".format(decoded_tcp["payload"]))

            print("--------------------------------------------------------------------")

    except KeyboardInterrupt:
        print("Stopping the sniffer.")


if __name__ == "__main__":
    main()
