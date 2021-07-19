
#include <sniffer_sess.h>
#include <sniffer_cfg.h>

#include <sniffer_mysql.h>
#include <sniffer_oracle.h>

#include <sniffer_log.h>

unordered_map<string,struct sniffer_session*> g_sessions;

void sniffer_session_log(sniffer_session * sess,bool isNew)
{
    cJSON * root = cJSON_CreateObject();
    cJSON * pValues = cJSON_CreateObject();
    if(!pValues || !root)
    {
        ERROR_LOG("sniffer_sess.cpp:sniffer_session_log() cJSON_CreateObject(<root> <propertyValues>) error %s",cJSON_GetErrorPtr());
        return;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);

    sess->from_upstream = !strcasecmp(sess->from_ip->buf,sniffer_cfg_capip().c_str());

    char id[64] = {0};
    char pid[64] = {0};

    //propertyValues。
    sniffer_log_uuid(id);
    sniffer_log_uuid(pid);

    cJSON_AddItemToObject(pValues,"id",cJSON_CreateString(id));
    cJSON_AddItemToObject(pValues,"pid",cJSON_CreateString(pid));

    if(sess->from_upstream) //来自服务器端。
    {
        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->to_port));

        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->from_port));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->to_port));

        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->from_port));
    }

    if(sess->login_user)
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateString(sess->login_user->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateNull());
    }

    cJSON_AddItemToObject(pValues,"s_body",cJSON_CreateNull());

    if(sess->login_with_schema)
    {
        cJSON_AddItemToObject(pValues,"s_database",cJSON_CreateString(sess->login_with_schema->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_database",cJSON_CreateNull());
    }

    cJSON_AddItemToObject(pValues,"session_id",cJSON_CreateString(sess->uuid->buf));

    cJSON_AddItemToObject(pValues,"session_time",cJSON_CreateNumber(sniffer_log_time_ms()));

    if(isNew)
    {
        cJSON_AddItemToObject(pValues,"session_type",cJSON_CreateString("login"));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"session_type",cJSON_CreateString("exit"));
    }

    cJSON_AddItemToObject(pValues,"op_begin_time",cJSON_CreateNumber(sess->op_start));
    cJSON_AddItemToObject(pValues,"op_end_time",cJSON_CreateNumber(sess->op_end));
    cJSON_AddItemToObject(pValues,"exe_time",cJSON_CreateNumber(sess->op_end - sess->op_start));

    cJSON_AddItemToObject(pValues,"sql_string",cJSON_CreateNull());

    if(isNew)
    {
        cJSON_AddItemToObject(pValues,"err_code",cJSON_CreateNumber(sess->err_code));
        if(sess->err_msg)
        {
            cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateString(sess->err_msg->buf));
        }
        else
        {
            cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateNull());
        }
    }
    else
    {
        cJSON_AddItemToObject(pValues,"err_code",cJSON_CreateNull());
        cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateNull());
    }

    cJSON_AddItemToObject(pValues,"effect_rows",cJSON_CreateNumber(0));

    cJSON_AddItemToObject(pValues,"db_type",cJSON_CreateString(sniffer_DB_TYPE_string(sess->db_type)));

    //完善body。
    cJSON_AddItemToObject(root,"app",cJSON_CreateString("nebula"));
    cJSON_AddItemToObject(root,"name",cJSON_CreateString("DB_DYNAMIC"));
    cJSON_AddItemToObject(root,"key",cJSON_CreateString(sess->from_upstream?sess->to_ip->buf:sess->from_ip->buf));
    cJSON_AddItemToObject(root,"value",cJSON_CreateNumber(1.0));
    cJSON_AddItemToObject(root,"timestamp",cJSON_CreateNumber(sniffer_log_time_ms()));
    cJSON_AddItemToObject(root,"propertyValues",pValues);

    sniffer_kafka_body(root);

    cJSON_Delete(root);
}

void sniffer_sql_log(sniffer_session * sess)
{
    cJSON * root = cJSON_CreateObject();
    cJSON * pValues = cJSON_CreateObject();
    if(!pValues || !root)
    {
        ERROR_LOG("sniffer_sess.cpp:sniffer_sql_log() cJSON_CreateObject(<root> <propertyValues>) error %s",cJSON_GetErrorPtr());
        return;
    }

    sess->from_upstream = !strcasecmp(sess->from_ip->buf,sniffer_cfg_capip().c_str());

    char id[64] = {0};
    char pid[64] = {0};

    //propertyValues。
    sniffer_log_uuid(id);
    sniffer_log_uuid(pid);

    cJSON_AddItemToObject(pValues,"id",cJSON_CreateString(id));
    cJSON_AddItemToObject(pValues,"pid",cJSON_CreateString(pid));

    if(sess->from_upstream) //来自服务器端。
    {
        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->to_port));

        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->from_port));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->to_port));

        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->from_port));
    }

    if(sess->login_user)
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateString(sess->login_user->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateNull());
    }

    if(sess->login_with_schema)
    {
        cJSON_AddItemToObject(pValues,"s_database",cJSON_CreateString(sess->login_with_schema->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_database",cJSON_CreateNull());
    }

    cJSON_AddItemToObject(pValues,"s_body",cJSON_CreateNull());

    cJSON_AddItemToObject(pValues,"session_id",cJSON_CreateString(sess->uuid->buf));
    cJSON_AddItemToObject(pValues,"session_time",cJSON_CreateNumber(sniffer_log_time_ms()));

    cJSON_AddItemToObject(pValues,"session_type",cJSON_CreateString("execute"));

    cJSON_AddItemToObject(pValues,"op_begin_time",cJSON_CreateNumber(sess->op_start));
    cJSON_AddItemToObject(pValues,"op_end_time",cJSON_CreateNumber(sess->op_end));
    cJSON_AddItemToObject(pValues,"exe_time",cJSON_CreateNumber(sess->op_end - sess->op_start));

    if(sess->current_sql)
    {
        cJSON_AddItemToObject(pValues,"sql_string",cJSON_CreateString(sess->current_sql->buf));
        
        destroy_sniffer_buf(sess->current_sql);
        sess->current_sql = nullptr;
    }
    else
    {
        cJSON_AddItemToObject(pValues,"sql_string",cJSON_CreateNull());
    }

    cJSON_AddItemToObject(pValues,"err_code",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"effect_rows",cJSON_CreateNumber(0));

    cJSON_AddItemToObject(pValues,"db_type",cJSON_CreateString(sniffer_DB_TYPE_string(sess->db_type)));

    //完善body。
    cJSON_AddItemToObject(root,"app",cJSON_CreateString("nebula"));
    cJSON_AddItemToObject(root,"name",cJSON_CreateString("DB_DYNAMIC"));
    cJSON_AddItemToObject(root,"key",cJSON_CreateString(sess->from_upstream?sess->to_ip->buf:sess->from_ip->buf));
    cJSON_AddItemToObject(root,"value",cJSON_CreateNumber(1.0));
    cJSON_AddItemToObject(root,"timestamp",cJSON_CreateNumber(sniffer_log_time_ms()));
    cJSON_AddItemToObject(root,"propertyValues",pValues);

    sniffer_kafka_body(root);

    cJSON_Delete(root);
}

static sniffer_session * sniffer_session_init()
{
    sniffer_session * sess = (struct sniffer_session*)zmalloc(sizeof(sniffer_session));

    sess->from_ip = nullptr;
    sess->from_mac = nullptr;

    sess->to_ip = nullptr;
    sess->to_mac = nullptr;

    sess->login_user = nullptr;
    sess->login_with_schema = nullptr;

    sess->current_sql = nullptr;
    sess->os_info = nullptr;
    sess->client_info = nullptr;

    sess->db_features = nullptr;
    sess->from_upstream = false;

    sess->uuid = nullptr;

    sess->err_msg = nullptr;
    sess->err_code = 0;

    return sess;
}

static void sniffer_session_delete(sniffer_session * sess)
{
    if(sess)
    {
        destroy_sniffer_buf(sess->from_ip);
        destroy_sniffer_buf(sess->from_mac);

        destroy_sniffer_buf(sess->to_ip);
        destroy_sniffer_buf(sess->to_mac);

        destroy_sniffer_buf(sess->login_user);
        destroy_sniffer_buf(sess->login_with_schema);

        destroy_sniffer_buf(sess->current_sql);
        destroy_sniffer_buf(sess->os_info);
        destroy_sniffer_buf(sess->client_info);

        if(sess->db_features)
        {
            zfree(sess->db_features);
            sess->db_features = nullptr;
        }

        destroy_sniffer_buf(sess->uuid);

        if(sess->err_msg)
        {
            destroy_sniffer_buf(sess->err_msg);
        }

        zfree(sess);
        sess = nullptr;
    }
}

void sniffer_session_key(tcp_stream stream,string &key)
{
    /*
        key_format:
            client_ip:client_port server_ip:server_port.
    */
    string cap_ip = sniffer_cfg_capip();
    if(0 == strcasecmp(cap_ip.c_str(),stream.from_ip.c_str()))
    {
        key = stream.to_ip;
        key = key + ":";
        key = key + to_string(stream.to_port);

        key = key + "<>";

        key = key + stream.from_ip;
        key = key + ":";
        key = key + to_string(stream.from_port);
    }
    else
    {
        key = stream.from_ip;
        key = key + ":";
        key = key + to_string(stream.from_port);

        key = key + "<>";

        key = key + stream.to_ip;
        key = key + ":";
        key = key + to_string(stream.to_port);
    }
}

int sniffer_session_add(const char * key,tcp_stream stream)
{
    int ret = 0;

    auto it = g_sessions.find(key);
    if(it != g_sessions.end())
    {
        return 0;
    }

    sniffer_session * sess = sniffer_session_init();

    sess->db_type = sniffer_cfg_dbtype();

    sess->from_ip = init_sniffer_buf(stream.from_ip.c_str());
    sess->from_port = stream.from_port;
    sess->from_mac = init_sniffer_buf(stream.from_mac.c_str());

    sess->to_ip = init_sniffer_buf(stream.to_ip.c_str());
    sess->to_port = stream.to_port;
    sess->to_mac = init_sniffer_buf(stream.to_mac.c_str());
    
    if(sess->db_type == DB_TYPE_MYSQL)
    {
        INFO_LOG("sniffer_sess.cpp:sniffer_session_add() new_session db_type %s","MySQL");

        sess->data_fun = dispatch_data_mysql;

        st_mysql * st = (struct st_mysql*)zmalloc(sizeof(struct st_mysql));
        st->query = false;
        st->compressed = false;
        st->ssl = false;
        st->capabilities = 0x807FF7FF;

        //默认使用高级别判断.
        st->isHandshakeV10 = true;
        st->isProtocolV41 = true;

        sess->db_features = (void*)st;
    }
    else if(sess->db_type == DB_TYPE_ORACLE)
    {
        INFO_LOG("sniffer_sess.cpp:sniffer_session_add() new_session db_type %s","Oracle");

        sess->data_fun = dispatch_data_oracle;

        st_oracle * st = (struct st_oracle*)zmalloc(sizeof(struct st_oracle));
        st->query = false;

        sess->db_features = (void*)st;
    }

    sess->uuid = init_sniffer_buf(40);
    sniffer_log_uuid(sess->uuid->buf);

    g_sessions.insert(make_pair(key,sess));

    return ret;
}

void sniffer_session_delete(const char * key)
{
    auto it = g_sessions.find(key);
    if(it != g_sessions.end())
    {
        sniffer_session * sess = it->second;

        INFO_LOG("sniffer_sess.cpp:sniffer_session_add() delete_session db_type %s",sniffer_DB_TYPE_string(sess->db_type));
        
        //删除会话信息.
        sess->op_start = sess->op_end = sniffer_log_time_ms();
        sniffer_session_log(sess,false);

        sniffer_session_delete(sess);
        g_sessions.erase(it);
    }
}

sniffer_session * sniffer_session_get(const char * key)
{
    auto it = g_sessions.find(key);
    if(it != g_sessions.end())
    {
        sniffer_session * sess = it->second;
        return sess;
    }

    return nullptr;
}
