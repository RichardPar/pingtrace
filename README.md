# pingtrace
A simple Netfilter-Bridge utility that shows the MAC addresses and some other
information on what interface the special PING message touched.


Building - just run MAKE 

sudo ./newping 192.168.2.113<br>
waiting on port 9090<br>
22 90 71 27 85 F4<br> 
PING INGRESS 586391A6B89E 2290712785F4 0469F8EAE6E3 eth1	6.541 ms
PING EGRESS  586391A6B89E 108DD7BE170C 0050B6032522 eth2	6.581 ms
RESP INGRESS 586391A6B89E 108DD7BE170C 0050B6032522 eth2	9.551 ms
RESP EGRESS  586391A6B89E 42E97A29D2AC 0469F8EAE6E3 eth1	9.583 ms
192.168.2.113 9.553 ms is Alive

Columns are 
PING/RESP DIRECTION NF_UID PACKET_ID MAC_ADDRESS INTERFACE  TIME

PING/RESP : Is the packet a ping or a ping_response

DIRECTION : Data flowing TO the CPU or Away

NF_UID    : Netfilter UID - every time the module is inmodded, it generates a 6 byte unique header 

PACKET_ID : Packet Identity - Every Egress has at least one INGRESS. This ties up what ports recived the transmitted packet

MAC_ADDRESS: The MAC of the port 

INTERFACE : Name of the interface

TIME      : How many miliseconds for Round Trip. Timer is started at PING origin.



