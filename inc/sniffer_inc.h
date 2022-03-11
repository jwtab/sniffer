
#ifndef SNIFFER_INC_H_H_
#define SNIFFER_INC_H_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <string>
#include <unordered_map>
#include <algorithm>

#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <sqlite3.h>

#include <cJSON.h>

using namespace  std;

enum DB_TYPE
{
    DB_TYPE_AUTO = 0,
    DB_TYPE_MYSQL,
    DB_TYPE_MARIADB,
    DB_TYPE_GBASE8A,
    DB_TYPE_ORACLE,
    DB_TYPE_POSTGRESQL,
    DB_TYPE_GREENPLUM,
    DB_TYPE_DM,
    DB_TYPE_INFORMIX,
    DB_TYPE_GBASE8S,
    DB_TYPE_GBASE8T,
    DB_TYPE_HIVE,
    DB_TYPE_MSSQL,
    DB_TYPE_DB2,
    DB_TYPE_MAX
};

enum LOG_TYPE
{
    LOG_TYPE_FATAL = 0,
    LOG_TYPE_ERROR,
    LOG_TYPE_WARN,
    LOG_TYPE_INFO,
    LOG_TYPE_DEBUG,
    LOG_TYPE_MAX
};

enum tcp_state
{
    NIDS_JUST_EST = 1,
    NIDS_DATA,
    NIDS_CLOSE,
    NIDS_RESET,
    NIDS_TIMED_OUT,
    NIDS_MAX
};

typedef struct tcp_stream
{
    string from_mac;
    string to_mac;

    string from_ip;
    string to_ip;

    int from_port;
    int to_port;

    tcp_state state;
}TCP_STREAM;

#endif //SNIFFER_INC_H_
