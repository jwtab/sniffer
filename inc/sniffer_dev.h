
#ifndef SNIFFER_DEV_H_H_
#define SNIFFER_DEV_H_H_

#include <sniffer_inc.h>

#include <pcap/pcap.h>


typedef int (*dispatch_fun)(tcp_stream stream,const char * data,int data_len);

int capdev_filter(const char *eth,const char * server_ip,int server_port);
int capdev_dispatch(dispatch_fun fun);
int capdev_uinit();

#endif //SNIFFER_DEV_H_
