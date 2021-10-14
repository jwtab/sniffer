
#include <sniffer_sess.h>
#include <sniffer_cfg.h>

#include <sniffer_mysql.h>
#include <sniffer_oracle.h>
#include <sniffer_tds.h>

#include <sniffer_log.h>

#include <random>

unordered_map<string,struct sniffer_session*> g_sessions;

string sniffer_strRand(int len)
{			
    char tmp; // tmp: 
    string buffer = "";
    
    random_device rd; 
    default_random_engine random(rd());
    
    for (int i = 0; i < len; i++) 
    { 
        tmp = random() % 36;	// 随机一个小于 36 的整数，0-9、A-Z 共 36 种字符 
        if (tmp < 10) 
        {			
            // 如果随机数小于 10，变换成一个阿拉伯数字的 ASCII 
            tmp += '0'; 
        }
        else 
        { 
            // 否则，变换成一个大写字母的 ASCII 
            tmp -= 10; 
            tmp += 'A'; 
        } 
        
        buffer += tmp; 
    } 
    
    return buffer;
}

void sniffer_session_log(sniffer_session * sess,bool isNew)
{
    ///string id = sniffer_strRand(24);

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

    //propertyValues。
    ///cJSON_AddItemToObject(pValues,"id",cJSON_CreateString(id.c_str()));
    ////cJSON_AddItemToObject(pValues,"pid",cJSON_CreateString("000000000000000000000000"));

    cJSON_AddItemToObject(pValues,"object_id",cJSON_CreateNumber(sniffer_cfg_objectid()));

    if(sess->from_upstream) //来自服务器端。
    {
        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->to_port));
        cJSON_AddItemToObject(pValues,"c_mac",cJSON_CreateString(sess->to_mac->buf));

        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->from_port));
        cJSON_AddItemToObject(pValues,"s_mac",cJSON_CreateString(sess->from_mac->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->to_port));
        cJSON_AddItemToObject(pValues,"s_mac",cJSON_CreateString(sess->to_mac->buf));

        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->from_port));
        cJSON_AddItemToObject(pValues,"c_mac",cJSON_CreateString(sess->from_mac->buf));
    }

    if(sess->login_user)
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateString(sess->login_user->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"username",cJSON_CreateNull());
    }

    if(sess->os_user)
    {
        cJSON_AddItemToObject(pValues,"c_os_user",cJSON_CreateString(sess->os_user->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_os_user",cJSON_CreateNull());
    }

    if(sess->os_info)
    {
        cJSON_AddItemToObject(pValues,"c_os",cJSON_CreateString(sess->os_info->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_os",cJSON_CreateNull());
    }

    if(sess->client_info)
    {
        cJSON_AddItemToObject(pValues,"c_client",cJSON_CreateString(sess->client_info->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_client",cJSON_CreateNull());
    }

    //三层审计相关.
    cJSON_AddItemToObject(pValues,"t_have",cJSON_CreateFalse());
    cJSON_AddItemToObject(pValues,"t_ip",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_port",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_mac",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_user",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_type",cJSON_CreateNull());

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

    cJSON_AddItemToObject(pValues,"op_type",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"op_object",cJSON_CreateNull());

    if(isNew)
    {
        cJSON_AddItemToObject(pValues,"err_code",cJSON_CreateNumber(sess->err_code));
        if(sess->err_msg && sess->err_code > 0)
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

    ///cJSON_AddItemToObject(root,"id",cJSON_CreateString(id.c_str()));
    ///cJSON_AddItemToObject(root,"pid",cJSON_CreateString("000000000000000000000000"));

    sniffer_kafka_body(root);

    cJSON_Delete(root);
}

void sniffer_sql_log(sniffer_session * sess)
{
    cJSON * root = cJSON_CreateObject();
    cJSON * pValues = cJSON_CreateObject();
    ///string id = sniffer_strRand(24);

    if(!pValues || !root)
    {
        ERROR_LOG("sniffer_sess.cpp:sniffer_sql_log() cJSON_CreateObject(<root> <propertyValues>) error %s",cJSON_GetErrorPtr());
        return;
    }

    sess->op_end = sniffer_log_time_ms();
    sess->from_upstream = !strcasecmp(sess->from_ip->buf,sniffer_cfg_capip().c_str());

    //propertyValues。
    ///cJSON_AddItemToObject(pValues,"id",cJSON_CreateString(id.c_str()));
    ///cJSON_AddItemToObject(pValues,"pid",cJSON_CreateString("000000000000000000000000"));

    cJSON_AddItemToObject(pValues,"object_id",cJSON_CreateNumber(sniffer_cfg_objectid()));

    if(sess->from_upstream) //来自服务器端。
    {
        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->to_port));
        cJSON_AddItemToObject(pValues,"c_mac",cJSON_CreateString(sess->to_mac->buf));

        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->from_port));
        cJSON_AddItemToObject(pValues,"s_mac",cJSON_CreateString(sess->from_mac->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_ip",cJSON_CreateString(sess->to_ip->buf));
        cJSON_AddItemToObject(pValues,"s_port",cJSON_CreateNumber(sess->to_port));
        cJSON_AddItemToObject(pValues,"s_mac",cJSON_CreateString(sess->to_mac->buf));

        cJSON_AddItemToObject(pValues,"c_ip",cJSON_CreateString(sess->from_ip->buf));
        cJSON_AddItemToObject(pValues,"c_port",cJSON_CreateNumber(sess->from_port));
        cJSON_AddItemToObject(pValues,"c_mac",cJSON_CreateString(sess->from_mac->buf));
    }

    //三层审计相关.
    cJSON_AddItemToObject(pValues,"t_have",cJSON_CreateFalse());
    cJSON_AddItemToObject(pValues,"t_ip",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_port",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_mac",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_user",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"t_type",cJSON_CreateNull());
    
    if(sess->os_user)
    {
        cJSON_AddItemToObject(pValues,"c_os_user",cJSON_CreateString(sess->os_user->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_os_user",cJSON_CreateNull());
    }

    if(sess->os_info)
    {
        cJSON_AddItemToObject(pValues,"c_os",cJSON_CreateString(sess->os_info->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_os",cJSON_CreateNull());
    }

    if(sess->client_info)
    {
        cJSON_AddItemToObject(pValues,"c_client",cJSON_CreateString(sess->client_info->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"c_client",cJSON_CreateNull());
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

    if(sess->db_type == DB_TYPE_MYSQL)
    {
        struct st_mysql *mysql = (struct st_mysql*)sess->db_features;
        if(mysql->affect_rows > 0 &&
            mysql->columns_select > 0)
        {
            cJSON_AddItemToObject(pValues,"s_body",mysql->select_body);
            if(mysql->columns_select_name)
            {
                for(uint32_t i = 0; i < mysql->columns_select; i++)
                {
                    if(mysql->columns_select_name[i])
                    {
                        destroy_sniffer_buf(mysql->columns_select_name[i]);
                        mysql->columns_select_name[i] = NULL;
                    }
                }

                zfree(mysql->columns_select_name);
                mysql->columns_select_name = NULL;
            }
        }
        else
        {
            cJSON_AddItemToObject(pValues,"s_body",cJSON_CreateNull());
        }
    }
    else if(sess->db_type == DB_TYPE_ORACLE)
    {
        struct st_oracle *oracle = (struct st_oracle*)sess->db_features;
        if(oracle->affect_rows > 0 &&
            oracle->columns_select > 0)
        {
            cJSON_AddItemToObject(pValues,"s_body",oracle->select_body);
            if(oracle->columns_select_name)
            {
                for(uint32_t i = 0; i < oracle->columns_select; i++)
                {
                    if(oracle->columns_select_name[i])
                    {
                        destroy_sniffer_buf(oracle->columns_select_name[i]);
                        oracle->columns_select_name[i] = NULL;
                    }
                }

                zfree(oracle->columns_select_name);
                oracle->columns_select_name = NULL;
            }
        }
        else
        {
            cJSON_AddItemToObject(pValues,"s_body",cJSON_CreateNull());
        }
    }
    else
    {
        cJSON_AddItemToObject(pValues,"s_body",cJSON_CreateNull());
    }
    
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

    cJSON_AddItemToObject(pValues,"op_type",cJSON_CreateNull());
    cJSON_AddItemToObject(pValues,"op_object",cJSON_CreateNull());

    cJSON_AddItemToObject(pValues,"err_code",cJSON_CreateNumber(sess->err_code));
    if(sess->err_msg && sess->err_code > 0)
    {
        cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateString(sess->err_msg->buf));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"err_msg",cJSON_CreateNull());
    }

    if(sess->db_type == DB_TYPE_MYSQL)
    {
        cJSON_AddItemToObject(pValues,"effect_rows",cJSON_CreateNumber(((struct st_mysql*)sess->db_features)->affect_rows));
    }
    else if(sess->db_type == DB_TYPE_ORACLE)
    {
        cJSON_AddItemToObject(pValues,"effect_rows",cJSON_CreateNumber(((struct st_oracle*)sess->db_features)->affect_rows));
    }
    else
    {
        cJSON_AddItemToObject(pValues,"effect_rows",cJSON_CreateNumber(0));
    }

    cJSON_AddItemToObject(pValues,"db_type",cJSON_CreateString(sniffer_DB_TYPE_string(sess->db_type)));

    //完善body。
    cJSON_AddItemToObject(root,"app",cJSON_CreateString("nebula"));
    cJSON_AddItemToObject(root,"name",cJSON_CreateString("DB_DYNAMIC"));
    cJSON_AddItemToObject(root,"key",cJSON_CreateString(sess->from_upstream?sess->to_ip->buf:sess->from_ip->buf));
    cJSON_AddItemToObject(root,"value",cJSON_CreateNumber(1.0));
    cJSON_AddItemToObject(root,"timestamp",cJSON_CreateNumber(sniffer_log_time_ms()));
    cJSON_AddItemToObject(root,"propertyValues",pValues);

    ///cJSON_AddItemToObject(root,"id",cJSON_CreateString(id.c_str()));
    ///cJSON_AddItemToObject(root,"pid",cJSON_CreateString("000000000000000000000000"));

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
        destroy_sniffer_buf(sess->os_user);
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
    
    sess->os_info = NULL;
    sess->os_user = NULL;
    sess->client_info = NULL;

    if(sess->db_type == DB_TYPE_MYSQL ||
        sess->db_type == DB_TYPE_MARIADB ||
        sess->db_type == DB_TYPE_GBASE8A)
    {
        INFO_LOG("sniffer_sess.cpp:sniffer_session_add() new_session LIKE_db_type %s","MySQL");

        sess->data_fun = dispatch_data_mysql;

        st_mysql * st = (struct st_mysql*)zmalloc(sizeof(struct st_mysql));
        if(st)
        {
            st->query = false;
            st->compressed = false;
            st->ssl = false;
            st->capabilities = 0x807FF7FF;

            //默认使用高级别判断.
            st->isHandshakeV10 = true;
            st->isProtocolV41 = true;
            st->columns_select_type = nullptr;
            
            st->downstream_buf = init_sniffer_buf(4096);
        }

        sess->db_features = (void*)st;
    }
    else if(sess->db_type == DB_TYPE_ORACLE)
    {
        INFO_LOG("sniffer_sess.cpp:sniffer_session_add() new_session db_type %s","Oracle");

        sess->data_fun = dispatch_data_oracle;

        st_oracle * st = (struct st_oracle*)zmalloc(sizeof(struct st_oracle));

        st->upstream_buf = init_sniffer_buf(256);
        st->downstream_buf = init_sniffer_buf(256);

        st->dataID_query = 0;
        st->callID_query = 0;

        st->columns_select = 0;
        st->columns_select_type = NULL;
        st->columns_select_name = NULL;

        sess->db_features = (void*)st;
    }
    else if(sess->db_type == DB_TYPE_INFORMIX ||
        sess->db_type == DB_TYPE_GBASE8S ||
        sess->db_type == DB_TYPE_GBASE8T)
    {

    }
    else if(sess->db_type == DB_TYPE_HIVE)
    {

    }
    else if(sess->db_type == DB_TYPE_DM)
    {
        
    }
    else if(sess->db_type == DB_TYPE_POSTGRESQL ||
            sess->db_type == DB_TYPE_GREENPLUM)
    {
        
    }
    else if(sess->db_type == DB_TYPE_MSSQL)
    {
        sess->data_fun = dispatch_data_tds;

        st_tds * st = (struct st_tds*)zmalloc(sizeof(struct st_tds));

        st->upstream_buf = init_sniffer_buf(1024);
        st->downstream_buf = init_sniffer_buf(1024);

        sess->db_features = (void*)st;
    }
    else if(sess->db_type == DB_TYPE_DB2)
    {
        
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
