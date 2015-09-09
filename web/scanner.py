import socket
import threading
import struct
from ctypes import *
import re
import subprocess
from netaddr import IPAddress,IPNetwork



hostup = []



class IP(Structure):
    _fields_ = [
        ("ihl",c_ubyte,4),
        ("version",c_ubyte,4),
        ("tos",c_ubyte),
        ("len",c_ushort),
        ("id",c_ushort),
        ("offset",c_ushort),
        ("ttl",c_ubyte),
        ("protocol_num",c_byte),
        ("sum",c_ushort),
        ("src",c_ulong),
        ("dst",c_ulong)
    ]
    def __new__(self,socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self,socket_buffer = None):
        self.protocol_map = {1:'ICMP',6:'TCP',17:'UDP'}
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ("type",c_ubyte),
        ("code",c_ubyte),
        ("checksum",c_ushort),
        ("unused",c_ushort),
        ("next_hop_mtu",c_ushort)
    ]
    def __new__(self,socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self,socket_buffer = None):
        pass

def udp_sender(magic_message,subnet):
    sender = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    print "[*] sending udp pack"
    for port in range(65536):
        for ip in subnet:
            try:
                sender.sendto(magic_message,("%s" % ip,port))
            except:
                pass
    print "[*] finish send"
    return

def getIpGateway():
    command = "ifconfig|grep 'inet'"
    result = subprocess.check_output(command,shell = True)
    target = re.compile("inet\s*addr:(\d+\.\d+\.\d+\.\d+)\s+Bcast:(\d+\.\d+\.\d+\.\d+)\s+Mask:")
    result = target.findall(result)
    return result[0][0],result[0][1]

def main():
    
    host,gateway = getIpGateway()    
    subnet =  IPNetwork(host[0:host.rfind(".")+1]+ "0/16")
    hostup.append(host)
    hostup.append(gateway)
    magic_message = "PYTHON!"
    print "host: %s,gateway: %s" % (host,gateway)
    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    t = threading.Thread(target = udp_sender,args = (magic_message,subnet))
    t.start()
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        ip = IPAddress(ip_header.src_address)
        if ip_header.protocol == "ICMP" and ip in subnet and ip not in hostup:
            if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                hostup.append(ip)
                print "HOst UP:%s" % ip
        
    return

def test():
    return
if __name__ == "__main__":
    #test()
    main()