arp-request-sniffer

1.create object pointer for pcap_t so we could stop pcap_loop() cleanly with ctrl+c

pcap_t *handle;

2.define signal handler for ctrl+c, inside is logic of breakin pcap_loop()

void handle_sigint(int sig) {
    (void) sig;
    pcap_breakloop(handle);
}

3. define function which will be called by pcap for every captured packet. as argument it gets packet pointer. other arguments unused.

void arp_packet_handler(
    u_char *user,
    const struct pcap_pkthdr *header,
    const u_char *packet
) 

then we create struct ether_header object pointer name it *eth and then we cast packet pointer to struct ether_header and assign it to our object
this will make it easier to access its fields, just eth. will show them.

then we see what protocol frame carries, and if its not arp, we return nothing;

    if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
        return;

then we create structu ether_arp object pointer name it *arp and then we cast packet pointer to struct ether_arp and assign it to our object. this way we have packets arp header in our object. 

    struct ether_arp *arp =
        (struct ether_arp *) (packet + sizeof(struct ether_header));


then we use our *arp object to what value its ar_op field has. it tells us whether its arp request or arp response, if its not request we return nothing.


    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
        return;

then we create two struct in_addr objects, sender_ip and target_ip.

from our arp object we retrieve sender ip and target ip and assign them to our objects. arp_spa = Sender ip,  arp_tpa = Target ip.

    memcpy(&sender_ip, arp->arp_spa, sizeof(sender_ip));
    memcpy(&target_ip, arp->arp_tpa, sizeof(target_ip));



4. in main() we define buffer for libpcap error message

    char errbuf[PCAP_ERRBUF_SIZE];
5. we create  struct bpf_program fp; object which will hold the compiled BPF filter.

6. Capture filter expression. "arp" tells libpcap to capture only ARP packets.
 
    char filter_exp[] = "arp";

7. open network interface by assigning pcap_open_live() to our previously defined pcap_t *handle; object. pcap_open_live() gets those arguments: interface name, BUFSIZ: max bytes per packet to capture, 1: enable promiscuous mode, 1000: read timeout in milliseconds, errbuf: buffer for error messages.

 handle = pcap_open_live(
        argv[1],
        BUFSIZ,
        1,
        1000,
        errbuf
    );

8. now we compile our BPF filter from human readable to bytecode which runs on kernel space. Only packets matching the BPF filter are copied. 

pcap_compile(
    handle,        // pcap capture handle (opened interface, link-layer info)
    &fp,            // output: compiled BPF filter program stored here
    filter_exp,     // human-readable filter string (e.g. "arp")
    0,              // optimization flag (1 = optimize filter, 0 = no optimization)
    net             // IPv4 netmask used for filters like "net x.x.x.x", 0 in this case not used 
);

9. register signal handler for ctrl+c. 

    signal(SIGINT, handle_sigint);

10. start capturing loop with pcap_loop() arguments: 

     *  - handle: capture session
     *  - -1: capture packets indefinitely
     *  - arp_packet_handler: callback function
     *  - NULL: user data passed to callback


    pcap_loop(handle, -1, arp_packet_handler, NULL);















