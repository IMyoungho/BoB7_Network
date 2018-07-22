#include "come_on_packet.h"

void come_on_packet(parse *ps)
{
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    const u_int8_t *packet;
    struct pcap_pkthdr *pkthdr;
    pcd=pcap_open_live(ps->using_interface(),BUFSIZ,1,1,errbuf);
    int number=1;
    while(true)
    {
        ret=pcap_next_ex(pcd, &pkthdr, &packet);
        switch (ret)
        {
            case 1:
            {
//              cout << "Packet is coming" << endl;
                //int packet_len = pkthdr->len;
                struct ether_header *ep= (struct ether_header*)packet;
                ps->get_ether_header(ep);
                if(ep->ether_type==ntohs(ETHERTYPE_IP))
                {
//                  cout << "IP packet is comming" <<endl;
                    struct iphdr *iph = (struct iphdr*)(packet+sizeof(ether_header));
                    ps->get_ip_header(iph);
                    if(iph->protocol==0x11)
                    {
//                      cout << ">> UDP packet is comming" << endl;
//                      struct udphdr *udph = (struct udphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                    }
                    else if(iph->protocol==0x06)
                    {
//                      cout << ">> TCP packet is comming" << endl;
                        struct tcphdr *tcph = (struct tcphdr*)(packet+sizeof(ether_header)+iph->ihl*4);
                        packet+=sizeof(ether_header)+iph->ihl*4+tcph->doff*4;
                        cout << "\n======================PACKET INFO "<< number << "=====================" <<   endl;
                        ps->get_tcp_header_and_data(tcph,(uint8_t*)packet);
                        ps->header_print();
                        number++;
                        if(ntohs(iph->tot_len)-iph->ihl*4-tcph->doff*4>=16)
                            ps->data_print(16);
                    }
                }
//              if(ep->ether_type==ntohs(ETHERTYPE_ARP))r
//                  cout << "ARP packet is comming" << endl;
            }
            break;
            case 0:
                continue;
            case -1:
            {
                cout << ">> Error \n";
                pcap_close(pcd);
                sleep(1);
                pcd = pcap_open_live(ps->using_interface(), BUFSIZ, 1 , 1, errbuf);
            }
            break;
            case -2:
            {
                cout << "EOF\n";
            }
            break;
            default:
            break;
        }
    }
}
