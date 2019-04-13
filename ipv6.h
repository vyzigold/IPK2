#pragma once

#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <string.h>
#include <regex>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>

#include "common.h"

using namespace std;

namespace ipv6 {

int ipv6_scan(string target, string ports_tcp, string ports_udp, char * ip_address, char const *interface_address);

//checksum function from https://www.linuxquestions.org/questions/programming-9/raw-sockets-checksum-function-56901/
/**
 * @brief Calculates checksum for TCP and IP
 * @param buf Pointer to stuff to calculate the checksum from
 * @param len Length of the thing to calculate the checksum for
 * @return checksum
 */
unsigned short csum(unsigned short *buf, int len);

//inspired by example at https://www.tenouk.com/Module43a.html
/**
 * @brief Opens socket and initializes every structure needed for packet construction
 * @param sock Variable to save socket descriptor to
 * @param ip IP header structure that should get initialized
 * @param tcp TCP header structure that should get initialized
 * @param dst Socket address to initialize
 * @param address Address of the scanning target
 * @param src_address Address of interface to scan from
 * @return Returns 0 if everything got successfuly initialized othervise returns non 0
 */
int tcp_scan_init(int &sock, struct ip6_hdr * &ip, struct tcphdr * &tcp, sockaddr_in6 &dst, const char* address, const char *src_address);

/**
 * @brief Sends one SYN packet to the target
 * @param sock Socket descriptor
 * @param buffer Packet to send
 * @param ip IP header of the packet
 * @param tcp TCP header of the packet
 * @param src Socket address structure of the socket
 * @param port Port to scan
 * @return Returns 0 for success or non 0 for failure
 */
int tcp_scan_port(int sock, char* buffer, struct ip6_hdr *ip, struct tcphdr *tcp, sockaddr_in6 src, int port);

/**
 * @brief Finds IP of the target
 * @param ip Buffer to save the IP to
 * @param hostname Hostname or IP address of the target
 * @return Returns 0 for success or non 0 for failure
 */
int get_ip(char *ip, string hostname);

/**
 * @brief Initializes and activetes packet capture
 * @param error_buffer Buffer for error message
 * @return Pointer to handle or NULL for failure
 */
pcap_t *pcap_handle_init(char *error_buffer);

/**
 * @brief Read captured packets and find answer from target
 * @param handle Packet capture handle (has to be initialized and activated)
 * @param error Buffer for error message
 * @param ip Targets IP address
 * @param port Scanned port
 * @return 1 for filtered, 2 for opened, 3 for closed
 */
int get_answer_tcp(pcap_t *handle, char *error, char *ip, int port);

/**
 * @brief Captures a sent packet to determine the IP address of interface it came out from
 * @param src_ip Buffer to fill the IP in
 * @param handle Capture handle has to be activated before the packet is sent
 * @param error Buffer for error messages
 * @param dest_ip IP of the target
 * return Returns the IP as an network order integer or 0 on failure
 */
int get_source_ip(char *src_ip, char *dest_ip);

/**
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
int tcp_scan(int sock, char *buffer, struct ip6_hdr *ip, struct tcphdr *tcp, struct sockaddr_in6 src, char *ip_address, string ports_tcp, pcap_t *handle);

/**
 * @brief Sends one UDP datagram to the target
 * @param sock Socket descriptor
 * @param buffer Packet to send
 * @param ip IP header of the packet
 * @param udp UDP header of the packet
 * @param src Socket address structure of the socket
 * @param port Port to scan
 * @return Returns 0 for success or non 0 for failure
 */
int udp_scan_port(int sock, char* buffer, struct ip6_hdr *ip, struct udphdr *udp, sockaddr_in6 src, int port);

/**
 * @brief Opens socket and initializes every structure needed for packet construction everything else should be initialized from packet sent via TCP to obtain source address
 * @param sock Variable to save socket descriptor to
 * @param buffer Packet buffer
 * @param udp UDP header structure that should get initialized
 * @return Returns 0 if everything got successfuly initialized othervise returns non 0
 */
int udp_scan_init(int &sock, char *buffer, struct udphdr * &udp);

/**
 * @brief Read captured packets and find answer from target
 * @param handle Packet capture handle (has to be initialized and activated)
 * @param error Buffer for error message
 * @param ip Targets IP address
 * @param port Scanned port
 * @return 1 for opened, 2 for closed/filtered
 */
int get_answer_udp(pcap_t *handle, char *error, char *ip, int port);

/**
 * @brief Does the UDP scan
 * @param buffer Packet with most of the needed info (doesn't have to include right checksums and ports)
 * @param ip The IP header structure of the packet
 * @param src The sockaddr_in structure of the socket
 * @param ip_address Scanned IP address as a string
 * @param ports_udp Ports to scan (can be a single port, list, or range of ports)
 * @param handle Initialized libpcap handle for getting responses
 * @return Returns 0 for success and non-zero for failure
 */
int udp_scan(char *buffer, struct ip6_hdr *ip, struct sockaddr_in6 src, char *ip_address, string ports_udp, pcap_t *handle);
}
