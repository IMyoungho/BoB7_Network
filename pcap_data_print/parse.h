#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>

using namespace std;


class parse{
private:
    char *interface;
    struct ether_header *eh;
    struct iphdr *ih;
    struct tcphdr *th;
    uint8_t packet[16];
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    void print_mac(char *str, uint8_t mac[6]);
    void get_ether_header(struct ether_header *eth);
    void get_ip_header(struct iphdr *ip);
    void get_tcp_header_and_data(struct tcphdr *tp, uint8_t *packet);
    void header_print();
    void data_print();
};


#endif // PARSE_H
