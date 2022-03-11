
#ifndef SNIFFER_LOG_H_H_
#define SNIFFER_LOG_H_H_

#include <sniffer_inc.h>

void sniffer_log(LOG_TYPE t,const char * format,...);

void sniffer_log_uuid(const char * key,char * uuid);
void sniffer_log_uuid_del(const char * key,char * uuid);

void sniffer_kafka_log(const char * log,uint32_t log_len);
void sniffer_kafka_body(cJSON * body);

int sniffer_kafka_init();
void sniffer_kafka_uninit();

string sniffer_current_time();

char * sniffer_DB_TYPE_string(DB_TYPE t);

uint64_t sniffer_log_time_ms();

#define FATAL_LOG(fmt,...) sniffer_log(LOG_TYPE_FATAL,fmt,__VA_ARGS__)
#define ERROR_LOG(fmt,...) sniffer_log(LOG_TYPE_ERROR,fmt,__VA_ARGS__)
#define WARN_LOG(fmt,...) sniffer_log(LOG_TYPE_WARN,fmt,__VA_ARGS__)
#define INFO_LOG(fmt,...) sniffer_log(LOG_TYPE_INFO,fmt,__VA_ARGS__)
#define DEBUG_LOG(fmt,...) sniffer_log(LOG_TYPE_DEBUG,fmt,__VA_ARGS__)

#endif //SNIFFER_LOG_H_
