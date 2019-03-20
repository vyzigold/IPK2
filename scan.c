#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string.h>
#include <regex>
#include <arpa/inet.h>


#define BUFFER_SIZE 8192

using namespace std;
void print_usage()
{
    //most of the next line copied from:
    //https://wis.fit.vutbr.cz/FIT/st/course-sl.php?id=671342&item=73049&cpa=1
    //author probably: Veselý Vladimír, Ing., Ph.D. (DIFS)
    //hope this is enough
    cerr << endl << "./ipk-scan -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]" << endl;
}

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

int parse_ports(string ports)
{
    int delimiter_ind = ports.find(",-");
    return 0;
}

//checksum function from https://www.tenouk.com/Module43a.html file rawtcp.c
unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for(sum=0; len>0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

//inspired from example at https://www.tenouk.com/Module43a.html
int tcp_scan_init(int &sock, struct iphdr * &ip, struct tcphdr * &tcp, sockaddr_in &src, const char* address)
{
    sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock < 0)
    {
        cerr << "Could not create socket" << endl;
        return -1;
    }

    src.sin_family = AF_INET;

    // Source port, can be any, modify as needed
    src.sin_port = htons(1234);

    // Source IP, can be any, modify as needed
    inet_pton(AF_INET, address, &(src.sin_addr.s_addr));

    // IP structure
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 16;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->check = 0; // Done by kernel
    ip->saddr = inet_addr("0.0.0.0");
    ip->daddr = inet_addr(address);

    tcp->source = htons(1234);
    tcp->seq = htonl(1);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->window = htons(32767);
    tcp->check = 0; // Done by kernel
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
    tcp->dest = htons(port);
    ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcphdr)));

    if(sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &src, sizeof(src)) < 0)
    {
        cerr << "Could not send the packet" << endl;
        return 1;
    }
    return 0;
}


int main(int argc, char *argv[])
{

    string ports_tcp;
    string ports_udp;
    string target;

    int rc;
    if((rc = get_args(argc, argv, ports_tcp, ports_udp, target)))
    {
        cerr << endl << "Argument parsing error" << endl;
        return rc;
    }

    cout << "tcp: " << ports_tcp << endl 
         << "udp: " << ports_udp << endl
         << "target: " << target << endl;

    //regex r(target); // \d.\d?\d?\.\d.\d?\d?\.\d.\d?\d?\.\d.\d?\d?\

    //networking part
    
    char buffer[BUFFER_SIZE];

    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in src;
    int sock;

    memset(buffer, 0, BUFFER_SIZE);
    if(tcp_scan_init(sock, ip, tcp, src, target.c_str()) != 0)
    {
        cerr << "Could not init scan" << endl;
        return 1;
    }

    int (*get_next_port)(string, bool);
    int port;
 
    if(ports_tcp != "")
    {
        if(ports_tcp.find(',') != string::npos)
            get_next_port = next_in_list;

        else if(ports_tcp.find('-') != string::npos)
            get_next_port = next_in_range;
        
        else
            get_next_port = next_in_solo;

        while((port = get_next_port(ports_tcp, false)) >= 0)
        {
            tcp_scan_port(sock, buffer, ip, tcp, src, port);
        }
    }
    
    if(ports_udp != "")
    {
        if(ports_udp.find(',') != string::npos)
            get_next_port = next_in_list;

        else if(ports_udp.find('-') != string::npos)
            get_next_port = next_in_range;
        
        else
            get_next_port = next_in_solo;
    
        port = get_next_port(ports_udp, true);
        if(port >= 0)
            cout << "udp: " << port << endl;
        while((port = get_next_port(ports_udp, false)) >= 0)
            cout << "udp: " << port << endl;
    }

    return 0;
}
