import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 
parentdir = os.path.dirname(parentdir)
sys.path.insert(0,parentdir) 

from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest
import random

myip = "172.20.0.139"
destip = "10.200.0.10"

def send_request(dest, destport, request):
    max = 3
    counter = 0
    while counter < max:
        try:
            #SEND SYN
            syn = IP(dst=dest) / TCP(sport=random.randint(1025,65500), dport=destport, flags='S')
            #GET SYNACK
            syn_ack = sr1(syn)
            #Send ACK
            ack = IP(dst=dest) / TCP(dport=destport, sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
            ack_resp = send(ack)
            #Send the HTTP GET
            resp = sr1(IP(dst=dest) / TCP(dport=destport, sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='P''A') / request)
            print("response: " + str(resp))
            counter = max
        except Exception as ex:
            print(ex)
            counter += 1

def main():
    # rdpcap comes from scapy and loads in our pcap file
    packets = rdpcap(str(currentdir) + '/wiredump.pcapng')
    packCount = 1
    # Let's iterate through every packet
    for packet in packets:
        # try:
        #     packet.show()
        # except Exception as ex:
        #     print(ex)
            
        if packet.haslayer(HTTPRequest):
            httplay = packet.getlayer(HTTPRequest)
            iplay = packet.getlayer(IP)
            tcplay = packet.getlayer(IP)
            if iplay.src == myip and iplay.dst == destip:
                print("Package " + str(packCount) + ":")
                packet.show()
                req = httplay.self_build()
                if not type(req) is str:
                    req = req.decode("utf-8")
                send_request(iplay.dst, iplay.dport, req)
                packCount = packCount + 1
  
if __name__ == '__main__':
    main()