#include "ipv4.h"

using namespace std;

namespace ipv4 {

int ipv4_scan(string target, string ports_tcp, string ports_udp, char *ip_address, char const *interface_address)
{

    //start capturing packets
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_handle_init(error_buffer);
    if(handle == NULL)
    {
        cerr << "Could not initialze structures needed for getting incomming packets. Maybe you forgot sudo." << error_buffer;
        return 1;
    }

    //packet headers init
    char buffer[BUFFER_SIZE];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in src;
    int sock;

    memset(buffer, 0, BUFFER_SIZE);

    if(tcp_scan_init(sock, ip, tcp, src, ip_address, "0.0.0.0") != 0)
    {
        cerr << "Could not init scan" << endl;
        return 1;
    }

    //determining the source IP
    char src_ip[16];
    if(get_source_ip(src_ip, ip_address))
    {
        cerr << "Could not get source ip address" << endl;
        close(sock);
        return 1;
    }
    if(strcmp(interface_address, ""))
        strcpy(src_ip, interface_address);
    inet_pton(AF_INET, src_ip, &ip->saddr);

    cout << "Interesting ports on " << target << "(" << ip_address << "):" << endl;
    cout << "PORT\tSTATE" << endl;
    //tcp scan
    if(ports_tcp != string(""))
    {
        if(tcp_scan(sock, buffer, ip, tcp, src, ip_address, ports_tcp, handle))
        {
            cerr << "TCP scanning error" << endl;
            pcap_close(handle);
            close(sock);
            return 1;
        }
    }
    
    close(sock);
    //udp scan
    if(ports_udp != string(""))
    {
        if(udp_scan(buffer, ip, src, ip_address, ports_udp, handle))
        {
            cerr << "UDP scanning error" << endl;
            pcap_close(handle);
            return 1;
        }
    }

    //cleanup
    pcap_close(handle);
    return 0;
}

unsigned short csum(unsigned short *buf, int len)
{
    int sum = 0;
    u_short answer = 0;
    u_short *w = buf;
    int nleft = len;
    while (nleft > 1)  {
            sum += *w++;
            nleft -= 2;
    }

    if (nleft == 1) {
    *(u_char *)(&answer) = *(u_char *)w ;
    sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

int tcp_scan_init(int &sock, struct iphdr * &ip, struct tcphdr * &tcp, sockaddr_in &dst, const char* address, const char *src_address)
{
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0)
    {
        cerr << "Could not create socket" << endl;
        return -1;
    }

    dst.sin_family = AF_INET;

    // Source port
    dst.sin_port = htons(0);

    inet_pton(AF_INET, address, &(dst.sin_addr.s_addr));

    // IP structure
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 16;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->check = 0; 
    ip->saddr = inet_addr(src_address);
    ip->daddr = inet_addr(address);

    //TCP structure
    tcp->source = htons(50357);
    tcp->seq = htonl(11111);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->window = htons(32767);
    tcp->check = 0; 
    tcp->rst = 0;
    tcp->urg_ptr = 0;
    
    int one = 1;
    int *ptr_one = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, ptr_one, sizeof(one)) < 0)
    {
        cerr << "Could not setsockopt" << endl;
        return 1;
    }
    return 0;
}

int tcp_scan_port(int sock, char* buffer, struct iphdr *ip, struct tcphdr *tcp, sockaddr_in src, int port)
{
    ip->check = 0;
    tcp->check = 0;
    tcp->dest = htons(port);
    
    //initialize pseudoheader for TCP checksum computation
    struct pseudohdr  {
	  struct in_addr source_address;
	  struct in_addr dest_address;
	  unsigned char zero;
	  unsigned char protocol;
	  unsigned short length;
	  } pseudoheader;

    char pseudopacket[sizeof(struct pseudohdr) + sizeof(struct tcphdr)];
    memset(pseudopacket, 0, sizeof(struct pseudohdr) + sizeof(struct tcphdr));

    pseudoheader.protocol = IPPROTO_TCP;
    pseudoheader.length = htons(sizeof(struct tcphdr));
    pseudoheader.zero = 0;
    pseudoheader.source_address.s_addr = ip->saddr;
    pseudoheader.dest_address.s_addr = ip->daddr;

    memcpy(pseudopacket, &pseudoheader, sizeof(struct pseudohdr));
    memcpy((pseudopacket + sizeof(struct pseudohdr)), (char *) tcp, sizeof(struct tcphdr));

    //compute checksums
    tcp->check = csum((unsigned short *) (pseudopacket), sizeof(pseudopacket));
    ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

    //send SYN packet
    if(sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &src, sizeof(src)) < 0)
    {
        cerr << "Could not send the packet" << endl;
        return 1;
    }
    return 0;
}

int get_ip(char *ip, string hostname)
{
    //regex matches only correct IPv4 addresses (0-255.0-255.0-255.0-255)
    //upgrading the virtual machine so it has more recent compiler and more recent regex library
    //would really help, in this the [x-y] notation doesn't work yet
    if(regex_match(hostname, regex("^(((0|1|2|3|4|5|6|7|8|9)(0|1|2|3|4|5|6|7|8|9)?)|(1(0|1|2|3|4|5|6|7|8|9)?(0|1|2|3|4|5|6|7|8|9)?)|(2(0|1|2|3|4)(0|1|2|3|4|5|6|7|8|9)?)|(25(0|1|2|3|4|5)?))\\.(((0|1|2|3|4|5|6|7|8|9)(0|1|2|3|4|5|6|7|8|9)?)|(1(0|1|2|3|4|5|6|7|8|9)?(0|1|2|3|4|5|6|7|8|9)?)|(2(0|1|2|3|4)(0|1|2|3|4|5|6|7|8|9)?)|(25(0|1|2|3|4|5)?))\\.(((0|1|2|3|4|5|6|7|8|9)(0|1|2|3|4|5|6|7|8|9)?)|(1(0|1|2|3|4|5|6|7|8|9)?(0|1|2|3|4|5|6|7|8|9)?)|(2(0|1|2|3|4)(0|1|2|3|4|5|6|7|8|9)?)|(25(0|1|2|3|4|5)?))\\.(((0|1|2|3|4|5|6|7|8|9)(0|1|2|3|4|5|6|7|8|9)?)|(1(0|1|2|3|4|5|6|7|8|9)?(0|1|2|3|4|5|6|7|8|9)?)|(2(0|1|2|3|4)(0|1|2|3|4|5|6|7|8|9)?)|(25(0|1|2|3|4|5)?))$")))
    {
        strcpy(ip, hostname.c_str());
        return 0;
    }
    struct hostent *entity;
    if((entity = gethostbyname(hostname.c_str())) == NULL)
    {
        return 1;
    }
    struct in_addr **addresses = (struct in_addr **) entity->h_addr_list;
    if(addresses[0] == NULL)
    {
        return 1;
    }
    strcpy(ip, inet_ntoa(*addresses[0]));
    return 0;
}

pcap_t *pcap_handle_init(char *error_buffer)
{
    error_buffer[0] = 0;
    pcap_t *handle = pcap_create("any", error_buffer);
    if(handle == NULL)
        return NULL;

    if(pcap_set_immediate_mode(handle, 1) != 0)
        return NULL;

    if(pcap_set_timeout(handle, 500) != 0)
        return NULL;

    if(pcap_activate(handle) != 0)
        return NULL;
    return handle;
}

int get_answer_tcp(pcap_t *handle, char *error, char *ip, int port)
{
    struct pcap_pkthdr packet_header;
    char src_addr[16];
    while(1)
    {
        //get the next captured packet
        const unsigned char *packet = pcap_next(handle, &packet_header);
        if(packet == NULL)
        {
            return 1;
        }

        //figure out header lengths and beginings of headers
        struct ether_header *eth_hdr = (struct ether_header *) packet;
        int eth_hdr_len = 16;
        struct iphdr *ip_header = (struct iphdr *) (packet + eth_hdr_len);
        int ip_header_len = (*((char *)ip_header)) & 0x0F;
        ip_header_len *= 4;
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + eth_hdr_len + ip_header_len);

        //prints some of the TCP and IP header
#ifdef DEBUGG_INFO
        cout << "addr_s raw: " << ip_header->saddr << endl;
        cout << "ack: " << tcp_header->ack << endl;
        cout << "dest: " << ntohs(tcp_header->dest) << endl;
        cout << "source: " << ntohs(tcp_header->source) << endl;
        cout << "seq: " << tcp_header->seq << endl;
        cout << "syn: " << tcp_header->syn << endl;
        cout << "rst: " << tcp_header->rst << endl;
        cout << "ip_csum: " << ip_header->check << endl;
        cout << "tcp_csum: " << tcp_header->check << endl;
#endif

        struct in_addr addr;
        addr.s_addr = ip_header->saddr;
        if(ip_header->protocol == 6 && !strcmp(inet_ntoa(addr), ip))
        {
            if(ntohs(tcp_header->source) != port)
                continue;
            
            if(tcp_header->rst)
                return 3;

            if(tcp_header->ack)
                return 2;
        }
    }
    return 0;
}

unsigned int get_source_ip(char * src_ip, char *dest_ip)
{
    int socke = socket(AF_INET, SOCK_DGRAM, 0);
    if(socke == -1)
    {
        cerr << "could not create socket" << endl;
        return 1;
    }
    sockaddr_in addr;
    struct sockaddr_in name;
    socklen_t len = sizeof(addr);

    if(inet_pton(AF_INET, dest_ip, &addr) != 1)
    {
        cout << "conversion error" <<  endl;
        return 1;
    }
    addr.sin_family = AF_INET;

    if(connect(socke, (struct sockaddr *) &addr, sizeof(addr)))
    {
        cerr << "Could not connect to host: " << errno << endl;
        return 1;
    }

    if(getsockname(socke, (struct sockaddr *) &name, &len))
    {
        cerr << "Could not get sockname" << endl;
        return 1;
    }

    if(inet_ntop(AF_INET, &name.sin_addr, src_ip, 16) == NULL)
    {
        cerr << "Conversion error" << endl;
        return 1;
    }
    close(socke);
    return 0;
}

int tcp_scan(int sock, char *buffer, struct iphdr *ip, struct tcphdr *tcp, struct sockaddr_in src, char *ip_address, string ports_tcp, pcap_t *handle)
{
    int (*get_next_port)(string, bool);
    int port;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];

    //set the capture filter
    char filter_exp[100];
    strcpy(filter_exp, "host ");
    strcat(filter_exp, ip_address);
    strcat(filter_exp, " and tcp");

    if(pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Bad filter: " << filter_exp << endl;
        return 1;
    }
    if(pcap_setfilter(handle, &filter) == -1)
    {
        cerr << "Could not set filter" << endl;
        return 1;
    }

    //determine in witch format the ports were given
    if(ports_tcp.find(',') != string::npos)
        get_next_port = next_in_list;

    else if(ports_tcp.find('-') != string::npos)
        get_next_port = next_in_range;
    
    else
        get_next_port = next_in_solo;

    //the scan
    while((port = get_next_port(ports_tcp, false)) >= 0)
    {
        tcp_scan_port(sock, buffer, ip, tcp, src, port);
        int result = get_answer_tcp(handle, error_buffer, ip_address, port);

        if(result == 1)
        {
            tcp_scan_port(sock, buffer, ip, tcp, src, port);
            result = get_answer_tcp(handle, error_buffer, ip_address, port);
        }

        if(result == 1)
            cout << port << "/tcp\tfiltered" << endl;

        if(result == 2)
            cout << port << "/tcp\topened" << endl;

        if(result == 3)
            cout << port << "/tcp\tclosed" << endl;
    }
    return 0;
}

int udp_scan_port(int sock, char* buffer, struct iphdr *ip, struct udphdr *udp, sockaddr_in src, int port)
{
    ip->check = 0;
    udp->check = 0;
    udp->dest = htons(port);
    
    //initialize pseudoheader for UDP checksum computation
    struct pseudohdr  {
	  struct in_addr source_address;
	  struct in_addr dest_address;
	  unsigned char zero;
	  unsigned char protocol;
	  unsigned short length;
	  } pseudoheader;

    char pseudopacket[sizeof(struct pseudohdr) + sizeof(struct udphdr)];
    memset(pseudopacket, 0, sizeof(struct pseudohdr) + sizeof(struct udphdr));

    pseudoheader.protocol = IPPROTO_UDP;
    pseudoheader.length = htons(sizeof(struct udphdr));
    pseudoheader.zero = 0;
    pseudoheader.source_address.s_addr = ip->saddr;
    pseudoheader.dest_address.s_addr = ip->daddr;

    memcpy(pseudopacket, &pseudoheader, sizeof(struct pseudohdr));
    memcpy((pseudopacket + sizeof(struct pseudohdr)), (char *) udp, sizeof(struct udphdr));

    //compute checksums
    udp->check = csum((unsigned short *) (pseudopacket), sizeof(pseudopacket));
    ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct udphdr)));

    //send packet
    if(sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &src, sizeof(src)) < 0)
    {
        cerr << "Could not send the packet" << endl;
        return 1;
    }
    return 0;
}

int udp_scan_init(int &sock, char *buffer, struct udphdr * &udp)
{
    memset(buffer + sizeof(struct iphdr), 0, BUFFER_SIZE - sizeof(struct iphdr));
    udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    udp->check = 0;
    udp->dest = 0;
    udp->len = htons(sizeof(struct udphdr));
    udp->source = 13519;

    sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0)
    {
        cerr << "Could not create socket" << endl;
        return -1;
    }

    int one = 1;
    int *ptr_one = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, ptr_one, sizeof(one)) < 0)
    {
        cerr << "Could not setsockopt" << endl;
        return 1;
    }
    return 0;
}

int get_answer_udp(pcap_t *handle, char *error, char *ip, int port)
{
    struct pcap_pkthdr packet_header;
    char src_addr[16];
    while(1)
    {
        //get the next captured packet
        const unsigned char *packet = pcap_next(handle, &packet_header);
        if(packet == NULL)
        {
            return 1;
        }

        //figure out header lengths and beginings of headers
        struct ether_header *eth_hdr = (struct ether_header *) packet;
        int eth_hdr_len = 16;
        struct iphdr *ip_header = (struct iphdr *) (packet + eth_hdr_len);
        if(ip_header->protocol != 1)
            continue;
        int ip_header_len = (*((char *)ip_header)) & 0x0F;
        ip_header_len *= 4;
        struct icmphdr *icmp_header = (struct icmphdr *) (packet + eth_hdr_len + ip_header_len);

        struct in_addr addr;
        addr.s_addr = ip_header->saddr;
        //prints some of the TCP and IP header
#ifdef DEBUGG_INFO
        cout << "addr_s raw: " << ip_header->saddr << endl;
        cout << "ip_csum: " << ip_header->check << endl;
        cout << "ip_protocol: " << (int) ip_header->protocol << endl;
        cout << "icmp code: " << (int) icmp_header->code << endl;
        cout << "icmp type: " << (int) icmp_header->type << endl;
        cout << "should be equal:" << endl;
        cout << inet_ntoa(addr) <<  " = " << ip << endl;
        cout << (int) ip_header->protocol <<  " = 1" << endl;
#endif

        if(ip_header->protocol == 1 && 
           !strcmp(inet_ntoa(addr), ip) && 
           icmp_header->code == 3 && 
           icmp_header->type == 3)
        {
            return 2;
        }
    }
    return 0;
}

int udp_scan(char *buffer, struct iphdr *ip, struct sockaddr_in src, char *ip_address, string ports_udp, pcap_t *handle)
{
    struct udphdr *udp;
    int sock;
    if(udp_scan_init(sock, buffer, udp))
    {
        cout << "Could not initialize UDP scan";
        return 1;
    }
    ip->protocol = 17;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);

    int (*get_next_port)(string, bool);
    int port;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];

    //set the capture filter
    char filter_exp[100];
    strcpy(filter_exp, "host ");
    strcat(filter_exp, ip_address);
    strcat(filter_exp, " and icmp");

    if(pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        cerr << "Bad filter: " << filter_exp << endl;
        close(sock);
        return 1;
    }
    if(pcap_setfilter(handle, &filter) == -1)
    {
        cerr << "Could not set filter" << endl;
        close(sock);
        return 1;
    }

    //determine in which format the ports were given
    if(ports_udp.find(',') != string::npos)
        get_next_port = next_in_list;

    else if(ports_udp.find('-') != string::npos)
        get_next_port = next_in_range;
    
    else
        get_next_port = next_in_solo;

    //restart the port loading functions and get first port scanned
    port = get_next_port(ports_udp, true);
    if(port >= 0)
    {
        udp_scan_port(sock, buffer, ip, udp, src, port);
        int value = get_answer_udp(handle, error_buffer, ip_address, port);
        if(value == 1)
        {
            value = get_answer_udp(handle, error_buffer, ip_address, port);
            if(value == 1)
                cout << port << "/udp\topen" << endl;
        }
        if(value == 2)
            cout << port << "/udp\tclosed" << endl;
        if(value == 0)
        {
            cerr << "Error capturing ICMP packet" << endl;
        }
    }
    //rest of the scan
    while((port = get_next_port(ports_udp, false)) >= 0)
    {
        udp_scan_port(sock, buffer, ip, udp, src, port);
        int value = get_answer_udp(handle, error_buffer, ip_address, port);
        if(value == 1)
        {
            value = get_answer_udp(handle, error_buffer, ip_address, port);
            if(value == 1)
                cout << port << "/udp\topen" << endl;
        }
        if(value == 2)
            cout << port << "/udp\tclosed" << endl;
        if(value == 0)
        {
            cerr << "Error capturing ICMP packet" << endl;
        }
    }
    return 0;
}
}
