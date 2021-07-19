
#ifndef SNIFFER_SESS_H_H_
#define SNIFFER_SESS_H_H_

#include <sniffer_inc.h>
#include <sniffer_buf.h>

#include <unordered_map>

struct sniffer_session;
typedef int (*dispatch_data)(sniffer_session *session,const char * data,uint32_t data_len);

enum session_type
{
    SESSION_TYPE_START = 0,
    SESSION_TYPE_STOP,
    SESSION_TYPE_DATA,
    SESSION_TYPE_MAX
};

enum session_data_type
{
    SESSION_DATA_TYPE_QUERY = 0,
    SESSION_DATA_TYPE_RESULTSET,
    SESSION_DATA_TYPE_LOGIN,
    SESSION_DATA_TYPE_MAX
};

typedef struct sniffer_session
{
    sniffer_buf *from_mac;
    sniffer_buf *to_mac;

    sniffer_buf *from_ip;
    sniffer_buf *to_ip;

    int from_port;
    int to_port;

    sniffer_buf * uuid;

    bool from_upstream;

    DB_TYPE db_type;
    sniffer_buf *login_user;
    sniffer_buf *login_with_schema;

    sniffer_buf *current_sql;

    sniffer_buf *os_info;
    sniffer_buf *client_info;

    dispatch_data data_fun;
    
    uint64_t op_start;
    uint64_t op_end;

    //是否错误.
    uint32_t err_code;
    sniffer_buf * err_msg;

    void * db_features;

}SNIFFER_SESSION;

void sniffer_session_key(tcp_stream stream,string &key);

int sniffer_session_add(const char * key,tcp_stream stream);
void sniffer_session_delete(const char * key);
sniffer_session * sniffer_session_get(const char * key);

//上报日志.
void sniffer_session_log(sniffer_session * sess,bool isNew = true);
void sniffer_sql_log(sniffer_session * sess);

#endif //SNIFFER_SESS_H_
