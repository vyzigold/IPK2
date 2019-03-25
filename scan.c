#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>
#include <regex>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>

//#define DEBUGG_INFO
#define BUFFER_SIZE 40

using namespace std;

/***
 * @brief Prints program usage
 */
void print_usage()
{
    //most of the next line copied from:
    //https://wis.fit.vutbr.cz/FIT/st/course-sl.php?id=671342&item=73049&cpa=1
    //author probably: Veselý Vladimír, Ing., Ph.D. (DIFS)
    //hope this is enough
    cerr << endl << "./ipk-scan -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]" << endl;
}

/***
 * @brief Parses program arguments
 * @param argc Count of arguments
 * @param argv Program arguments from main()
 * @param ports_tcp String where the -pt argument should be saved
 * @param ports_udp String where the -pu argument should be saved
 * @param target String where the scan target should be saved
 * @return 0 for correct arguments, non zero for incorrect ones
 */
int get_args(int argc, char *argv[], string &ports_tcp, string &ports_udp, string &target)
{
    //get ports
    int option;
    while(getopt(argc, argv, "p") != -1)
    {
        if((option = getopt(argc, argv, "u:t:")) != 1)
        {
            
            switch(option)
            {
                case 'u':
                    ports_udp = optarg;
                    break;
                case 't':
                    ports_tcp = optarg;
                    break;
                default:
                    cerr << "Unknown program argument." << endl;
                    print_usage();
                    return 1;
            }
        }
    }

    //get the target
    if(argc == optind)
    {
        cerr << "You haven't specified the target." << endl;
        print_usage();
        return 2;
    }

    target = argv[optind];

    //check if there is any more arguments (there shouldn't be)
    int expected_argc = 2; //filename + target
    if(ports_tcp != "")
        expected_argc += 2;

    if(ports_udp != "")
        expected_argc += 2;

    if(argc != expected_argc)
    {
        cerr << "Too many arguments" << endl;
        print_usage();
        return 3;
    }
    return 0;
}

/***
 * @brief Finds next port from port range, restart = true for use on every new range
 * @param ports The port range to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_range(string ports, bool restart)
{
    static int last_port = -1;
    static int begining;
    static int end;
    int hyphon_ind = ports.find("-");
    size_t index;
    bool error = false;

    if(last_port == -1 || restart)
    {
        string begining_str = ports.substr(0, hyphon_ind);
        try
        {
            begining = stoi(begining_str, &index);
        }
        catch(exception e)
        {
            error = true;
        }

        if(error || begining_str[index] != '\0' || begining < 0)
        {
            cerr << "Wrong begining port number was given: " << begining_str << endl;
            return -2;
        }

        string end_str = ports.substr(hyphon_ind + 1);
        try
        {
            end = stoi(end_str, &index);
        }
        catch(exception e)
        {
            error = true;
        }

        if(error || end_str[index] != '\0' || end < 0)
        {
            cerr << "Wrong end port number was given: " << end_str << endl;
            return -2;
        }

        if(begining > end)
        {
            cerr << "Negative range was given." << endl;
        }

        last_port = begining -1;
    }
    
    last_port++;
    
    if(last_port > end)
        return -1;
    else
        return last_port;
}

/***
 * @brief Finds next port from port list, restart = true for use on every new list
 * @param ports The port list to get next from
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_list(string ports, bool restart)
{
    static int last_position;
    bool error = false;
    if(restart)
        last_position = 0;

    if(last_position == -1)
        return -1;

    int next_position = ports.find(',', last_position);

    string port_str = ports.substr(last_position, next_position - last_position);

    last_position = (next_position == string::npos) ? -1 : next_position + 1;
    
    size_t index;
    int port;

    try
    {
        port = stoi(port_str, &index);
    }
    catch(exception e)
    {
        error = true;
    }

    if(error || port_str[index] != '\0' || port < 0)
    {
        cerr << "Wrong port number was given." << endl;
        return -2;
    }

    return port;
}

/***
 * @brief Returns the solo port as an integer, works similarly as next_in_range and next_in_list
 * @param ports One port number
 * @param restart Bool if the search should be restarted
 * @return The port number
 */
int next_in_solo(string ports, bool restart)
{
    static int last_port = -1;
    size_t index;
    bool error = false;

    if(restart)
        last_port = -1;

    int port;
    try
    {
        port = stoi(ports, &index);
    }
    catch(exception e)
    {
        error = true;
    }

    if(error || ports[index] != '\0' || port < 0)
    {
        cerr << "Wrong port number was given." << endl;
        return -2;
    }

    if(last_port != port)
    {
        last_port = port;
        return port;
    }
    
    return -1;
}

//checksum function from https://www.linuxquestions.org/questions/programming-9/raw-sockets-checksum-function-56901/
/***
 * @brief Calculates checksum for TCP and IP
 * @param buf Pointer to stuff to calculate the checksum from
 * @param len Length of the thing to calculate the checksum for
 * @return checksum
 */
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

//inspired by example at https://www.tenouk.com/Module43a.html
/***
 * @brief Opens socket and initializes every structure needed for packet construction
 * @param sock Variable to save socket descriptor to
 * @param ip IP header structure that should get initialized
 * @param tcp TCP header structure that should get initialized
 * @param dst Socket address to initialize
 * @param address Address of the scanning target
 * @param src_address Address of interface to scan from
 * @return Returns 0 if everything got successfuly initialized othervise returns non 0
 */
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
    dst.sin_port = htons(1234);

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

/***
 * @brief Sends one SYN packet to the target
 * @param sock Socket descriptor
 * @param buffer Packet to send
 * @param ip IP header of the packet
 * @param tcp TCP header of the packet
 * @param src Socket address structure of the socket
 * @param port Port to scan
 * @return Returns 0 for success or non 0 for failure
 */
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

/***
 * @brief Finds IP of the target
 * @param ip Buffer to save the IP to
 * @param hostname Hostname or IP address of the target
 * @return Returns 0 for success or non 0 for failure
 */
int get_ip(char *ip, string hostname)
{
    //regex matches only correct IPv4 addresses (0-255.0-255.0-255.0-255)
    if(regex_match(hostname, regex("^((\\d\\d?)|(1\\d?\\d?)|(2[01234]\\d?)|(25[012345]?))\\.((\\d\\d?)|(1\\d?\\d?)|(2[01234]\\d?)|(25[012345]?))\\.((\\d\\d?)|(1\\d?\\d?)|(2[01234]\\d?)|(25[012345]?))\\.((\\d\\d?)|(1\\d?\\d?)|(2[01234]\\d?)|(25[012345]?))$")))
    {
        strcpy(ip, hostname.c_str());
        return 0;
    }
    struct hostent *entity;
    if((entity = gethostbyname(hostname.c_str())) == NULL)
    {
        cerr << "Invalid hostname or IP: " << hostname << endl;
        return 1;
    }
    struct in_addr **addresses = (struct in_addr **) entity->h_addr_list;
    if(addresses[0] == NULL)
    {
        cerr << "Error retrieving address of: " << hostname << endl;
    }
    strcpy(ip, inet_ntoa(*addresses[0]));
    return 0;
}

/***
 * @brief Initializes and activetes packet capture
 * @param error_buffer Buffer for error message
 * @return Pointer to handle or NULL for failure
 */
pcap_t *pcap_handle_init(char *error_buffer)
{
    error_buffer[0] = 0;
    pcap_t *handle = pcap_create("any", error_buffer);
    if(handle == NULL)
        return NULL;

    if(pcap_set_immediate_mode(handle, 1) != 0)
        return NULL;

    if(pcap_set_timeout(handle, 4000) != 0)
        return NULL;

    if(pcap_activate(handle) != 0)
        return NULL;
    return handle;
}

/***
 * @brief Read captured packets and find answer from target
 * @param handle Packet capture handle (has to be initialized and activated)
 * @param error Buffer for error message
 * @param ip Targets IP address
 * @param port Scanned port
 * @return 1 for filtered, 2 for opened, 3 for closed
 */
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

/***
 * @brief Captures a sent packet to determine the IP address of interface it came out from
 * @param src_ip Buffer to fill the IP in
 * @param handle Capture handle has to be activated before the packet is sent
 * @param error Buffer for error messages
 * @param dest_ip IP of the target
 * return Returns the IP as an network order integer or 0 on failure
 */
unsigned int get_source_ip(char * src_ip, pcap_t *handle, char *error, char *dest_ip)
{
    struct pcap_pkthdr packet_header;
    int src_addr;
    while(1)
    {
        //get next captured packet
        const unsigned char *packet = pcap_next(handle, &packet_header);
        if(packet == NULL)
        {
            return 0;
        }

        //determine the beginings of headers
        struct ether_header *eth_hdr = (struct ether_header *) packet;
        int eth_hdr_len = 16;
        struct iphdr *ip_header = (struct iphdr *) (packet + eth_hdr_len);
        int ip_header_len = (*((char *)ip_header)) & 0x0F;
        ip_header_len *= 4;
        struct tcphdr *tcp_header = (struct tcphdr *) (packet + eth_hdr_len + ip_header_len);

        struct in_addr addr;
        addr.s_addr = ip_header->daddr;
        if(!strcmp(inet_ntoa(addr), dest_ip))
        {
            addr.s_addr = ip_header->saddr;
            strcpy(src_ip, inet_ntoa(addr));
            return ip_header->saddr;
        }
    }
    return 0;
}

/***
 * @brief Does the TCP scan
 * @param sock Opened socket to scan on
 * @param buffer Packet with most of the needed info (doesn't have to include right checksums and ports)
 * @param ip The IP header structure of the packet
 * @param tcp The TCP header structure of the packet
 * @param src The sockaddr_in structure of the socket
 * @param ip_address Scanned IP address as a string
 * @param ports_tcp Ports to scan (can be a single port, list, or range of ports)
 * @param handle Initialized libpcap handle for getting responses
 * @return Returns 0 for success and non-zero for failure
 */
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
            result = get_answer_tcp(handle, error_buffer, ip_address, port);

        if(result == 1)
            cout << port << "/tcp\tfiltered" << endl;

        if(result == 2)
            cout << port << "/tcp\topened" << endl;

        if(result == 3)
            cout << port << "/tcp\tclosed" << endl;
    }
    return 0;
}

/***
 * @brief Sends one UDP datagram to the target
 * @param sock Socket descriptor
 * @param buffer Packet to send
 * @param ip IP header of the packet
 * @param udp UDP header of the packet
 * @param src Socket address structure of the socket
 * @param port Port to scan
 * @return Returns 0 for success or non 0 for failure
 */
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

/***
 * @brief Opens socket and initializes every structure needed for packet construction everything else should be initialized from packet sent via TCP to obtain source address
 * @param sock Variable to save socket descriptor to
 * @param buffer Packet buffer
 * @param udp UDP header structure that should get initialized
 * @return Returns 0 if everything got successfuly initialized othervise returns non 0
 */
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

/***
 * @brief Read captured packets and find answer from target
 * @param handle Packet capture handle (has to be initialized and activated)
 * @param error Buffer for error message
 * @param ip Targets IP address
 * @param port Scanned port
 * @return 1 for opened, 2 for closed/filtered
 */
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

/***
 * @brief Does the UDP scan
 * @param buffer Packet with most of the needed info (doesn't have to include right checksums and ports)
 * @param ip The IP header structure of the packet
 * @param src The sockaddr_in structure of the socket
 * @param ip_address Scanned IP address as a string
 * @param ports_udp Ports to scan (can be a single port, list, or range of ports)
 * @param handle Initialized libpcap handle for getting responses
 * @return Returns 0 for success and non-zero for failure
 */
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
                cout << "UDP port " << port << " open" << endl;
        }
        if(value == 2)
            cout << "UDP port " << port << " closed" << endl;
        if(value == 0)
        {
            cerr << "Error capturing ICMP packet" << endl;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

    string ports_tcp;
    string ports_udp;
    string target;
    char ip_address[16];

    //parse the args
    int rc;
    if((rc = get_args(argc, argv, ports_tcp, ports_udp, target)))
    {
        cerr << endl << "Argument parsing error" << endl;
        return rc;
    }

#ifdef DEBUGG_INFO
    cout << "tcp: " << ports_tcp << endl 
         << "udp: " << ports_udp << endl
         << "target: " << target << endl;
#endif
    
    //figure out the targets IP address
    if(get_ip(ip_address, target) != 0)
    {
        cerr << "Could not get IP of: " << target << endl;
        return 1;
    }
    cout << "IP: " << ip_address << endl;

    //start capturing packets
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_handle_init(error_buffer);
    if(handle == NULL)
    {
        cerr << "Could not initialze structures needed for getting incomming packets" << error_buffer;
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
    if(tcp_scan_port(sock, buffer, ip, tcp, src, 80))
    {
        cerr << "Could not send packet to determine source IP address";
        close(sock);
        return 1;
    }
    if((ip->saddr = get_source_ip(src_ip, handle, error_buffer, ip_address)) == 0)
    {
        cerr << "Could not get source ip address" << endl;
        close(sock);
        return 1;
    }

    cout << "Interesting ports on " << target << "(" << src_ip << "):" << endl;
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
