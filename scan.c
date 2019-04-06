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

int main(int argc, char *argv[])
{

    string ports_tcp;
    string ports_udp;
    string target;
    char ip_address[40];

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
    if(ipv4::get_ip(ip_address, target) != 0)
    {
        cerr << "Could not get IP of: " << target << endl;
        return 1;
    }
    else
	return ipv4::ipv4_scan(target, ports_tcp, ports_udp, ip_address);

    return 0;
}
