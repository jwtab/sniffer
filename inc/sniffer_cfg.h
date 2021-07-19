
#ifndef SNIFFER_CFG_H_H_
#define SNIFFER_CFG_H_H_

#include <sniffer_inc.h>

typedef struct sniffer_config
{
    bool daemon;
    string cap_net;
    string cap_ip;
    int cap_port;

    string kafka;

    DB_TYPE db_type;

    LOG_TYPE log_type;
}SNIFFER_CONFIG;

int sniffer_cfg_init(int argc,char **argv);

int  sniffer_cfg_parse(int argc,char **argv);
void sniffer_cfg_print();
sniffer_config * sniffer_cfg_get();
bool sniffer_cfg_daemon();
LOG_TYPE sniffer_cfg_logtype();
DB_TYPE sniffer_cfg_dbtype();
string sniffer_cfg_capip();
string sniffer_cfg_kafka();

#endif //SNIFFER_CFG_H_
