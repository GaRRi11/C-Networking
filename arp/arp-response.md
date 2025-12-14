
## arp reply


from request we already know :

| Information          | Comes from             |
| -------------------- | ---------------------- |
| Who is asking?       | Sender MAC + Sender IP |
| What IP they want?   | Target IP              |
| Where to send reply? | Sender MAC             |



1.arp header:

instead of ARPOP_REQUEST we put ARPOP_REPLY

2.arp header:

instead of putting zeros in target mac:         0x00, 0x00, 0x00, 0x00, 0x00, 0x00

we put target devices mac

target mac:     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff

3.ethernet header:

in dst_mac instead of broadcast mac:         0xff, 0xff, 0xff, 0xff, 0xff, 0xff

we put target devices mac: 

target mac:     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff

4.arp header in src_ip we put ip we are pretending to be:

src_ip    = libnet_name2addr4(l, "192.168.1.1", LIBNET_RESOLVE);

5.arp header in dst_ip we put ip of target device.

target_ip = libnet_name2addr4(l, "192.168.1.15", LIBNET_RESOLVE);
