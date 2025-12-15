1.make devices override their arp cache.

Gratuitous / unsolicited ARP

Set target IP = broadcast or your own IP

Set destination MAC = broadcast (ff:ff:ff:ff:ff:ff:ff)

Send ARP reply without the target actually requesting it

uint8_t dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // broadcast

target_ip = src_ip; // your own IP

arp_tag = libnet_build_arp(..., ARPOP_REPLY, src_mac, (uint8_t*)&src_ip, target_mac, (uint8_t*)&target_ip,...)


This causes all devices to update the ARP cache → “override.”
