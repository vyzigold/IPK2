#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string>
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
#include <net/if.h>
#include <sys/ioctl.h>

#include "common.h"
#include "ipv4.h"
#include "ipv6.h"


using namespace std;

/**
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

/**
 * @brief Parses program arguments
 * @param argc Count of arguments
 * @param argv Program arguments from main()
 * @param ports_tcp String where the -pt argument should be saved
 * @param ports_udp String where the -pu argument should be saved
 * @param target String where the scan target should be saved
 * @return 0 for correct arguments, non zero for incorrect ones
 */
int get_args(int argc, char *argv[], string &ports_tcp, string &ports_udp, string &target, string &interface)
{
    //get ports
    int option;
    while((option = getopt(argc, argv, "pi:")) != -1)
    {
        if(option == 'p')
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
        else if(option == 'i')
        {
            interface = optarg;
        }
        else
        {
            cerr << "Unknown program argument." << endl;
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

    if(interface != "")
        expected_argc += 2;

    if(argc != expected_argc)
    {
        cerr << "Too many arguments" << endl;
        print_usage();
        return 3;
    }
    return 0;
}

int get_interface_IPs(string interface, string &ip4, string &ip6)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));

    //IPv4
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1)
    {
        cerr << "Could not create socket." << endl;
        return 1;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    memcpy(ifr.ifr_name, interface.c_str(), interface.size());

    if(ioctl(sock, SIOCGIFADDR, &ifr) != -1)
    {
        ip4 = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    }

    close(sock);
    memset(&ifr, 0, sizeof(struct ifreq));

    //IPv6
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if(sock == -1)
    {
        cerr << "Could not create socket." << endl;
        return 1;
    }

    ifr.ifr_addr.sa_family = AF_INET6;

    memcpy(ifr.ifr_name, interface.c_str(), interface.size());

    if(ioctl(sock, SIOCGIFADDR, &ifr) != -1)
    {
        char buffer[40];
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&ifr.ifr_addr)->sin6_addr, buffer, 40);
        ip6 = buffer;
    }

    close(sock);
    if(ip4 == "" && ip6 == "")
    {
        cerr << "Could not get interface IP" << endl;
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[])
{

    string ports_tcp;
    string ports_udp;
    string target;
    string interface;
    char target_ip4_address[40];
    char target_ip6_address[40];

    //parse the args
    int rc;
    if((rc = get_args(argc, argv, ports_tcp, ports_udp, target, interface)))
    {
        cerr << endl << "Argument parsing error" << endl;
        return rc;
    }

    string ip4;
    string ip6;

    if(interface != "")
    {
        if(get_interface_IPs(interface, ip4, ip6))
            return 1;
    }
    
    //figure out the targets IP address
    if(ipv4::get_ip(target_ip4_address, target) != 0)
    {
        strcpy(target_ip4_address, "");
    }
    if(ipv6::get_ip(target_ip6_address, target) != 0)
    {
        strcpy(target_ip6_address, "");
    }

#ifdef DEBUGG_INFO
    cerr << "tcp: " << ports_tcp << endl 
         << "udp: " << ports_udp << endl
         << "target: " << target << endl
         << "interface: " << interface << endl;
    cerr << "IPv4 address: " << ip4 << " IPv6 address: " << ip6 << endl;
    cerr << "Target IPv4: " << target_ip4_address 
         << " Target IPv6: " << target_ip6_address << endl;
#endif

    if(!strcmp(target_ip4_address, "") && !strcmp(target_ip6_address, ""))
    {
        cerr << "Could not get the IP address of: " << target << endl;
        return 1;
    }

    //target has ipv4 address and if the interface is set, it has ipv4 address
    if(strcmp(target_ip4_address, "") && (interface != "") == (ip4 != ""))
    {
        return ipv4::ipv4_scan(target, ports_tcp, ports_udp, target_ip4_address, ip4.c_str());
    }
    else if(strcmp(target_ip6_address, "") && (interface != "") == (ip6 != ""))
    {
        return ipv6::ipv6_scan(target, ports_tcp, ports_udp, target_ip6_address, ip6.c_str());
    }

    return 0;
}
