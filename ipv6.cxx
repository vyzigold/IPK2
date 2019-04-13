#include "ipv6.h"
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ether.h>

using namespace std;

namespace ipv6 {

int ipv6_scan(string target, string ports_tcp, string ports_udp, char *ip_address, char const *interface_address)
{
    //start capturing packets
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_handle_init(error_buffer);
    if(handle == NULL)
    {
        cerr << "Could not initialze structures needed for getting incomming packets: " << error_buffer << endl;
        cerr << "Maybe you forgot sudo?" << endl;
        return 1;
    }

    //packet headers init
    char buffer[BUFFER_SIZE];
    struct ip6_hdr *ip = (struct ip6_hdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct ip6_hdr));
    struct sockaddr_in6 src;
    int sock;

    memset(buffer, 0, BUFFER_SIZE);

    if(tcp_scan_init(sock, ip, tcp, src, ip_address, "::") != 0)
    {
        cerr << "Could not init scan" << endl;
        return 1;
    }

    //determining the source IP
    char src_ip[40];

    if(get_source_ip(src_ip, ip_address))
    {
        cerr << "Could not get source ip address" << endl;
        close(sock);
        return 1;
    }
    if(strcmp(interface_address, ""))
        strcpy(src_ip, interface_address);

    inet_pton(AF_INET6, src_ip, &ip->ip6_src);

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
    memset(buffer+sizeof(ip6_hdr), 0, BUFFER_SIZE - sizeof(ip6_hdr));
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

int tcp_scan_init(int &sock, struct ip6_hdr * &ip, struct tcphdr * &tcp, sockaddr_in6 &dst, const char* address, const char *src_address)
{
    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0)
    {
        cerr << "Could not create socket" << endl;
        return -1;
    }

    dst.sin6_family = AF_INET6;

    // Source port
    dst.sin6_port = htons(0);

    inet_pton(AF_INET6, address, &(dst.sin6_addr));

    // IP structure
    ip->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl((6 << 28) | (0 << 20) | 0);
    ip->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
    ip->ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;
    ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct tcphdr));

    if ((inet_pton (AF_INET6, src_address, &(ip->ip6_src))) != 1)
    {
        cerr << "Could not initialize ip structure" << endl;
        return -1;
    }

    if ((inet_pton (AF_INET6, address, &(ip->ip6_dst))) != 1)
    {
        cerr << "Could not initialize ip structure" << endl;
        return -1;
    }

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
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, ptr_one, sizeof(one)) < 0)
    {
        cerr << "Could not setsockopt" << endl;
        return 1;
    }
    return 0;
}

int tcp_scan_port(int sock, char* buffer, struct ip6_hdr *ip, struct tcphdr *tcp, sockaddr_in6 src, int port)
{
    tcp->check = 0;
    tcp->dest = htons(port);
    
    //initialize pseudoheader for TCP checksum computation
    struct pseudohdr  {
	  struct in6_addr source_address;
	  struct in6_addr dest_address;
          long length;
	  unsigned char zero[3];
	  unsigned char protocol;
	  } pseudoheader;

    char pseudopacket[sizeof(struct pseudohdr) + sizeof(struct tcphdr)];
    memset(pseudopacket, 0, sizeof(struct pseudohdr) + sizeof(struct tcphdr));
    memset(&pseudoheader, 0, sizeof(struct pseudohdr));

    pseudoheader.protocol = IPPROTO_TCP;
    pseudoheader.length = htonl(sizeof(struct tcphdr));
    pseudoheader.source_address = ip->ip6_src;
    pseudoheader.dest_address = ip->ip6_dst;
    pseudoheader.zero[0] = 0;
    pseudoheader.zero[1] = 0;
    pseudoheader.zero[2] = 0;

    memcpy(pseudopacket, &pseudoheader, sizeof(struct pseudohdr));
    memcpy((pseudopacket + sizeof(struct pseudohdr)), (char *) tcp, sizeof(struct tcphdr));

#ifdef DEBUGG_INFO
    cout << endl << "IPv6 TCP pseudoheader follows:" << endl;
    pseudohdr *phdr = &pseudoheader;
    cout << "pseudoheader checksum: " << csum((unsigned short *) phdr, sizeof(pseudoheader)/2) << endl;
    char addr[40];
    if(inet_ntop(AF_INET6, &pseudoheader.source_address, addr, 40) == NULL)
    {
        cout << "Could not convert source IP to string" << endl;
        return 1;
    }
    cout << "source_address: " << addr << endl;
    if(inet_ntop(AF_INET6, &pseudoheader.dest_address, addr, 40) == NULL)
    {
        cout << "Could not convert destination IP to string" << endl;
        return 1;
    }
    cout << "destination_address: " << addr << endl;
    cout << "Length as int: " << (int) pseudoheader.length << endl;
    cout << "Length in host order: " << ntohl(pseudoheader.length) << endl;
    cout << "Correct Length: " << sizeof(struct tcphdr) << endl;
    cout << "3 zeros byte by byte: " << (int) pseudoheader.zero[0] << " " << (int) pseudoheader.zero[1] << " " << (int) pseudoheader.zero[2] << " " << endl;
    cout << "protocol: " << (int) pseudoheader.protocol << endl;
#endif

    //compute checksums
    tcp->check = csum((unsigned short *) (pseudopacket), sizeof(pseudopacket));

    //send SYN packet
    if(sendto(sock, buffer, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &src, sizeof(src)) < 0)
    {
        cerr << "Could not send the packet: " << errno << endl;
        perror(NULL);
        return 1;
    }
    return 0;
}

int get_ip(char *ip, string hostname)
{
    //test if the hostname is a valid IPv6 address
    struct in6_addr addr_struct;
    if(inet_pton(AF_INET6, hostname.c_str(), &addr_struct) == 1)
    {
        strcpy(ip, hostname.c_str());
        return 0;
    }

    //try to convert the address
    struct addrinfo params;
    struct addrinfo *result;

    memset(&params, 0, sizeof(struct addrinfo));

    params.ai_family = AF_INET6;
    params.ai_socktype = SOCK_STREAM;
    params.ai_flags = AI_PASSIVE;
    params.ai_protocol = IPPROTO_TCP;
    params.ai_canonname = NULL;
    params.ai_addr = NULL;
    params.ai_next = NULL;
    int rc;

    if((rc = getaddrinfo(hostname.c_str(), NULL, &params, &result)))
    {
        cerr << "get info error: " << rc << endl;
        return 1;
    }

    if(inet_ntop(AF_INET6, &result->ai_addr->sa_data[6], ip, 40) == NULL)
    {
        cerr << "inet_ntop error" << endl;
        return 1;
    }
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
        struct ip6_hdr *ip_header = (struct ip6_hdr *) (packet + eth_hdr_len);
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + eth_hdr_len + sizeof(struct ip6_hdr));

        char addr[40];
        //prints some of the TCP and IP header
#ifdef DEBUGG_INFO
        cout << endl << "TCP PACKET RECIEVED:" << endl;
        cout << "ack: " << tcp_header->ack << endl;
        cout << "dest: " << ntohs(tcp_header->dest) << endl;
        cout << "source: " << ntohs(tcp_header->source) << endl;
        cout << "seq: " << tcp_header->seq << endl;
        cout << "syn: " << tcp_header->syn << endl;
        cout << "rst: " << tcp_header->rst << endl;
        cout << "tcp_csum: " << tcp_header->check << endl;
        cout << "expected IP: " << ip << endl;
        cout << "actual IP: " << inet_ntop(AF_INET6, &ip_header->ip6_src, addr, 40) << endl;
#endif

        if(ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP && 
                !strcmp(inet_ntop(AF_INET6, &ip_header->ip6_src, addr, 40), ip))
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

int get_source_ip(char * src_ip, char *dest_ip)
{
    int socke = socket(AF_INET6, SOCK_DGRAM, 0);
    if(socke == -1)
    {
        cerr << "could not create socket" << endl;
        return 1;
    }
    sockaddr_in6 addr;
    struct sockaddr_in6 name;
    socklen_t len = sizeof(addr);

    if(inet_pton(AF_INET6, dest_ip, &addr) != 1)
    {
        cout << "conversion error" <<  endl;
        return 1;
    }
    addr.sin6_family = 10;

    if(connect(socke, (struct sockaddr *) &addr, sizeof(addr)))
    {
        cerr << "Could not connect to host: " << errno << endl;
        perror(NULL);
        return 1;
    }

    if(getsockname(socke, (struct sockaddr *) &name, &len))
    {
        cerr << "Could not get sockname" << endl;
        return 1;
    }

    if(inet_ntop(AF_INET6, &name.sin6_addr, src_ip, 40) == NULL)
    {
        cerr << "Conversion error" << endl;
        return 1;
    }
    close(socke);
    return 0;
}

int tcp_scan(int sock, char *buffer, struct ip6_hdr *ip, struct tcphdr *tcp, struct sockaddr_in6 src, char *ip_address, string ports_tcp, pcap_t *handle)
{
    int (*get_next_port)(string, bool);
    int port;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];

    //set the capture filter
    char filter_exp[200];
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

int udp_scan_port(int sock, char* buffer, struct ip6_hdr *ip, struct udphdr *udp, sockaddr_in6 src, int port)
{
    udp->check = 0;
    udp->dest = htons(port);
    
    //initialize pseudoheader for UDP checksum computation
    struct pseudohdr  {
	  struct in6_addr source_address;
	  struct in6_addr dest_address;
          long length;
	  unsigned char zero[3];
	  unsigned char protocol;
	  } pseudoheader;

    char pseudopacket[sizeof(struct pseudohdr) + sizeof(struct udphdr)];
    memset(pseudopacket, 0, sizeof(struct pseudohdr) + sizeof(struct udphdr));
    memset(&pseudoheader, 0, sizeof(struct pseudohdr));

    pseudoheader.protocol = IPPROTO_UDP;
    pseudoheader.length = htonl(sizeof(struct udphdr));
    pseudoheader.zero[0] = 0;
    pseudoheader.zero[1] = 0;
    pseudoheader.zero[2] = 0;
    pseudoheader.source_address = ip->ip6_src;
    pseudoheader.dest_address = ip->ip6_dst;

    memcpy(pseudopacket, &pseudoheader, sizeof(struct pseudohdr));
    memcpy((pseudopacket + sizeof(struct pseudohdr)), (char *) udp, sizeof(struct udphdr));

    //compute checksums
    udp->check = csum((unsigned short *) (pseudopacket), sizeof(pseudopacket));

    //send packet
    if(sendto(sock, buffer, sizeof(struct ip6_hdr) + sizeof(struct udphdr), 0, (struct sockaddr *) &src, sizeof(src)) < 0)
    {
        cerr << "Could not send the packet" << endl;
        return 1;
    }
    return 0;
}

int udp_scan_init(int &sock, char *buffer, struct udphdr * &udp)
{
    memset(buffer + sizeof(struct ip6_hdr), 0, BUFFER_SIZE - sizeof(struct ip6_hdr));
    udp = (struct udphdr *) (buffer + sizeof(struct ip6_hdr));
    udp->check = 0;
    udp->dest = 0;
    udp->len = htons(sizeof(struct udphdr));
    udp->source = 13519;

    sock = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
    if(sock < 0)
    {
        cerr << "Could not create socket" << endl;
        return -1;
    }

    int one = 1;
    int *ptr_one = &one;
    if(setsockopt(sock, IPPROTO_IPV6, IPV6_HDRINCL, ptr_one, sizeof(one)) < 0)
    {
        cerr << "Could not setsockopt" << endl;
        return 1;
    }
    return 0;
}

int get_answer_udp(pcap_t *handle, char *error, char *ip, int port)
{
    struct pcap_pkthdr packet_header;
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
        struct ip6_hdr *ip_header = (struct ip6_hdr *) (packet + eth_hdr_len);
        struct icmp6_hdr *icmp_header = (struct icmp6_hdr *) (packet + eth_hdr_len + sizeof(ip6_hdr));

        char addr[40];
        if(inet_ntop(AF_INET6, &ip_header->ip6_src, addr, 40) == NULL)
            continue;
        //prints some of the TCP and IP header
#ifdef DEBUGG_INFO
        cout << endl << "UDP datagram recieved:" << endl;
        cout << "icmp code: " << (int) icmp_header->icmp6_code << endl;
        cout << "icmp type: " << (int) icmp_header->icmp6_type << endl;
        cout << "next: " << (int) ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt << endl;
        cout << "addr: " << addr << endl;
        cout << "ip: " << ip << endl;
#endif

        if(ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58 && 
           !strcmp(addr, ip) && 
           icmp_header->icmp6_code == 4 && 
           icmp_header->icmp6_type == 1)
        {
            return 2;
        }
    }
    return 0;
}

int udp_scan(char *buffer, struct ip6_hdr *ip, struct sockaddr_in6 src, char *ip_address, string ports_udp, pcap_t *handle)
{
    struct udphdr *udp;
    int sock;
    ip->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
    if(udp_scan_init(sock, buffer, udp))
    {
        cout << "Could not initialize UDP scan";
        return 1;
    }
    ip->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct udphdr));

    int (*get_next_port)(string, bool);
    int port;
    struct bpf_program filter;
    char error_buffer[PCAP_ERRBUF_SIZE];

    //set the capture filter
    char filter_exp[100];
    strcpy(filter_exp, "host ");
    strcat(filter_exp, ip_address);

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
        if(udp_scan_port(sock, buffer, ip, udp, src, port))
            return 1;
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
        if(udp_scan_port(sock, buffer, ip, udp, src, port))
            return 1;
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
