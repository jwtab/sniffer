
#include <sniffer_dev.h>

#include <sniffer_log.h>

static pcap_t * g_device = nullptr;
static int g_linktype;
static string g_server_ip = "";

static unsigned int sniffer_getLinkoffset(const unsigned char * data) 
{
    /* Only handle IP packets and 802.1Q VLAN tagged packets below. */
    if ((data[12] == 8 && data[13] == 0) || (data[12] == 0x86 && data[13] == 0xdd)) {
        /* Regular ethernet */
        return  14;
    } else if (data[12] == 0x81 && data[13] == 0) {
        if (data[16] == 0x81 && data[17] == 0) { // qinq double vlan tag
            return  22;
        } else {
            /* Skip 802.1Q VLAN and priority information */
            return 18;
        }
    } else if (data[12] == 0 && data[14] == 8 && data[15] == 0) {
        /* remote prober at any interface */
        return  16;
    } else if (data[12] == 0 && data[14] == 0x81 && data[18] == 8) {
        /* any and vlan */
        return  20;
    } else {
        /* non-ip frame */
        return 0;
    }
}

static void sniffer_dev_dump_info(struct tcp_stream *tcp_stream,struct ether_header *ethHdr,struct ip *ipHdr,struct tcphdr *tcpHdr)
{
    char ip_format[128] = {0};

    //MAC地址.
    for (size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        char format[4]= {0};

        sprintf(format,"%02x",ethHdr->ether_shost[i]);
        tcp_stream->from_mac += format;

        sprintf(format,"%02x",ethHdr->ether_dhost[i]);
        tcp_stream->to_mac += format;

        if(i != ETHER_ADDR_LEN - 1)
        {
            tcp_stream->from_mac += ":";
            tcp_stream->to_mac += ":";
        }
    }

    //ip
    sprintf(ip_format,"%u.%u.%u.%u",
            (ntohl(ipHdr->ip_src.s_addr) >> 24) & 0xff,
            (ntohl(ipHdr->ip_src.s_addr) >> 16) & 0xff,
            (ntohl(ipHdr->ip_src.s_addr) >> 8) & 0xff,
            (ntohl(ipHdr->ip_src.s_addr)) & 0xff);
    tcp_stream->from_ip = ip_format;

    sprintf(ip_format,"%u.%u.%u.%u",
            (ntohl(ipHdr->ip_dst.s_addr) >> 24) & 0xff,
            (ntohl(ipHdr->ip_dst.s_addr) >> 16) & 0xff,
            (ntohl(ipHdr->ip_dst.s_addr) >> 8) & 0xff,
            (ntohl(ipHdr->ip_dst.s_addr)) & 0xff);
    tcp_stream->to_ip = ip_format;

    //tcp_port
    #ifdef __linux__
        #if (defined (__FAVOR_BSD))
            tcp_stream->from_port = ntohs(tcpHdr->th_sport);
            tcp_stream->to_port = ntohs(tcpHdr->th_dport);
        #else
            tcp_stream->from_port = ntohs(tcpHdr->source);
            tcp_stream->to_port = ntohs(tcpHdr->dest);
        #endif
    #else
        tcp_stream->from_port = ntohs(tcpHdr->th_sport);
        tcp_stream->to_port = ntohs(tcpHdr->th_dport);
    #endif
}

static void sniffer_dev_state(struct tcp_stream *tcp_stream,struct tcphdr *tcpHdr)
{
    #ifdef __linux__
        #if (defined (__FAVOR_BSD))
            if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_SYN) )
            {
                tcp_stream->state = NIDS_JUST_EST;
            }

            if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_FIN))
            {
                tcp_stream->state = NIDS_CLOSE;
            }
        #else
            if(tcpHdr->ack && tcpHdr->syn)
            {
                tcp_stream->state = NIDS_JUST_EST;
            }

            if(tcpHdr->ack && tcpHdr->fin)
            {
                tcp_stream->state = NIDS_CLOSE;
            }
        #endif
    #else
        if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_SYN) )
        {
            tcp_stream->state = NIDS_JUST_EST;
        }

        if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_FIN))
        {
            tcp_stream->state = NIDS_CLOSE;
        }  
    #endif
}

static void sniffer_dev_dump(const unsigned char * cap_data,int cap_len,dispatch_fun fun)
{
    struct ether_header *ethHdr;    //以太网头部
    struct ip *ipHdr; 				//IP头结构
    struct tcphdr *tcpHdr; 			//TCP头结构

    struct tcp_stream stream;
    stream.state = NIDS_MAX;

    int offset = sniffer_getLinkoffset(cap_data);
    int payload_len = 0;

    //mac头
    ethHdr = (struct ether_header*)cap_data;
    //ip头
    ipHdr = (struct ip *) (cap_data + offset);

    //ipv6
    if(ipHdr->ip_v == 6)
    {
        DEBUG_LOG("sniffer_dev.cpp::sniffer_dev_dump() IPv6 DONT_DEAL %s","");
    }
    //ipv4
    else if(ipHdr->ip_v == 4)
    {
        unsigned int ipHdr_len = sizeof(unsigned int) * (ipHdr->ip_hl & 0xf);
        offset += ipHdr_len;

        //tcp头获取
        tcpHdr = (struct tcphdr *) (cap_data + offset);
        
        #ifdef __linux__
            #if (defined (__FAVOR_BSD))
                payload_len = cap_len - offset - sizeof(uint32_t)*tcpHdr->th_off;
            #else
                payload_len = cap_len - offset - sizeof(uint32_t)*tcpHdr->doff;
            #endif
        #else
            payload_len = cap_len - offset - sizeof(uint32_t)*tcpHdr->th_off;
        #endif

        DEBUG_LOG("sniffer_dev.cpp::sniffer_dev_dump() IPv4 cap_len %d,frame_len %d",cap_len,payload_len);

        sniffer_dev_dump_info(&stream,ethHdr,ipHdr,tcpHdr);
        if(payload_len > 0)
        {
            #ifdef __linux__
                #if (defined (__FAVOR_BSD))
                    if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_PUSH))
                    {
                        stream.state = NIDS_DATA;
                    }
                #else
                    if((tcpHdr->ack) && (tcpHdr->psh))
                    {
                        stream.state = NIDS_DATA;
                    }
                #endif
            #else
                if((tcpHdr->th_flags & TH_ACK) && (tcpHdr->th_flags & TH_PUSH))
                {
                    stream.state = NIDS_DATA;
                }
            #endif
        }
        else
        {
            sniffer_dev_state(&stream,tcpHdr);
        }

        offset = cap_len -payload_len;
        fun(stream,(const char *)(cap_data + offset),payload_len);
    }
}

int capdev_filter(const char *eth,const char * server_ip,int server_port)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program filter; 
    string filter_app = "ip and tcp and host ";
    bpf_u_int32 mask; 
    bpf_u_int32 net;

    filter_app = filter_app + server_ip;
    filter_app = filter_app + " and port ";
    filter_app = filter_app + to_string(server_port);

    g_device = pcap_open_live(eth,65536,1,10,errBuf);
    if(!g_device)  
    {
        FATAL_LOG("sniffer_dev.cpp:capdev_filter(%s) %s",eth,errBuf); 
        exit(1);
    }

    int ret = pcap_lookupnet(eth, &net, &mask, errBuf);

    ret = pcap_compile(g_device, &filter, filter_app.c_str(), 0, net);
    if(0 != ret)
    {
        ERROR_LOG("sniffer_dev.cpp:capdev_filter(%s) pcap_compile(%s) error %s",
            eth,filter_app.c_str(), pcap_geterr(g_device));
    }
    else
    {
        ret = pcap_setfilter(g_device, &filter);
        if(0 != ret)
        {
            ERROR_LOG("sniffer_dev.cpp:capdev_filter(%s) pcap_setfilter() error %s",eth,pcap_geterr(g_device));
        }
    }

    g_linktype = pcap_datalink(g_device);
    g_server_ip = server_ip;

    return ret;
}

int capdev_dispatch(dispatch_fun fun)
{
    if(!g_device)
    {
        return -1;
    }

    struct pcap_pkthdr *header; 
    const u_char *pkt_data;

    int ret = pcap_next_ex(g_device,&header,&pkt_data);
    if(1 == ret) //right
    {
        if(DLT_EN10MB != g_linktype)
        {
            return 0;
        }

        INFO_LOG("sniffer_dev.cpp:capdev_dispatch() pcap_next_ex() caplen %d,len %d",header->caplen,header->len);

        if(header->len < 64)
        {
            return 0;
        }

        sniffer_dev_dump(pkt_data,header->len,fun);
    }
    else if(0 == ret) //timeout
    {

    }
    else if(-1 == ret) //error
    {
        ERROR_LOG("sniffer_dev.cpp:capdev_filter() pcap_next_ex() error %s",pcap_geterr(g_device));
    }
    else if(-2 == ret) //read from save_file TO END.
    {
        ERROR_LOG("sniffer_dev.cpp:capdev_filter() pcap_next_ex() end_of_savefile error %s",pcap_geterr(g_device));
    }

    return 0;
}

int capdev_uinit()
{
    if(!g_device) 
    {
        pcap_close(g_device);
    }

    return 0;
}
