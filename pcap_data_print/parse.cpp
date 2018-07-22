#include "parse.h"

parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=2){
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "    >> 사용법 : <dev>\n";
        exit(1);
    }
    this->interface=argv[1];
}
char *parse::using_interface(){
    return this->interface;
}
void parse::print_mac(char *str, uint8_t mac[6]){
    sprintf(str,"%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}
void parse::get_ether_header(struct ether_header *eth){
    this->eh=eth;
}
void parse::get_ip_header(struct iphdr *ip){
    this->ih=ip;
}
void parse::get_tcp_header_and_data(struct tcphdr *tp, uint8_t *packet){
    this->th=tp;
    memcpy(this->packet,packet,16);
}
void parse::header_print(){
    char str_mac[15];
    char str_ip[32];
    this->print_mac(str_mac,this->eh->ether_shost);
    cout << "Src MAC = " << str_mac;
    this->print_mac(str_mac,this->eh->ether_dhost);
    cout << "\nDst MAC = " << str_mac << endl;
    inet_ntop(AF_INET,&(this->ih->saddr),str_ip,32);
    cout << "Src IP = " << str_ip << endl;
    inet_ntop(AF_INET,&(this->ih->daddr),str_ip,32);
    cout << "Dst IP = " << str_ip << endl;
    cout << "Src Port = " << ntohs(this->th->source) << endl;
    cout << "Dst Port = " << ntohs(this->th->dest) << endl;
}
void parse::data_print(int length){
    for(int i=0; i<length; i++)
        printf("%02x ", this->packet[i]);
    cout << endl;
}

