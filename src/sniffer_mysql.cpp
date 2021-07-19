
#include <sniffer_mysql.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

static uint32_t _mysql_lenenc(const char * data,uint32_t &offset,uint16_t &len_len)
{
    unsigned char flag = data[offset];
    uint32_t attrs_len = 0;

    if (flag <= 0xfb)
    {
		attrs_len = flag;
        offset = offset + 1;

        len_len = 1;
    }
    else if (flag == 0xfc)
    {
        attrs_len = (data[offset]&0xff) + ((data[offset + 1]&0xff) << 8);
        offset = offset + 2;

        len_len = 2;
    }
    else if (flag == 0xfd)
    {
        attrs_len = (data[offset]&0xff) + (data[offset + 1] << 8) + (data[offset + 2] << 16);
        offset = offset + 3;

        len_len = 2;
    }
    else if (flag == 0xfe)
    {
        attrs_len = (data[offset]&0xff) + (data[offset + 1] << 8) + (data[offset + 2] << 16) + (data[offset + 3] << 24);
        offset = offset + 4;

        len_len = 4;
    }

    return attrs_len;
}

static void dispatch_data_mysql_sql(string &sql,const char * data,int cnt)
{
    for(int i = 0; i < cnt; i++)
    {
        if(data[i] == '\n' || data[i] == '\t')
        {}
        else
        {
            sql = sql + data[i];
        }
    }
}

static void dispatch_data_mysql_upstream_RequestQuery(sniffer_session *session,const char * request_data,uint32_t data_len)
{
    uint32_t offset = 0;

    if(data_len <= 0)
    {
        return;
    }

    MYSQL_TEXT_PROTOCOL command_type = (MYSQL_TEXT_PROTOCOL)request_data[offset];

    struct st_mysql * st = (struct st_mysql*)session->db_features;
    if(st)
    {
        st->query = true;
    }

    string sql = "";

    offset = offset + 1;
    switch (command_type)
    {
    case COM_QUERY:
    case COM_CREATE_DB:
    case COM_DROP_DB:
        {
            dispatch_data_mysql_sql(sql,request_data + offset,data_len - offset);
            break;
        }
        
    case COM_STMT_PREPARE:
        {
            dispatch_data_mysql_sql(sql,request_data + offset,data_len - offset);
            break;
        }
        
    case COM_STMT_EXECUTE:
        {
            break;
        }

    case COM_INIT_DB:
        {
            sql = "use ";
            dispatch_data_mysql_sql(sql,request_data + offset,data_len - offset);
            break;
        }

    case COM_FIELD_LIST:
        {
            sql = "desc ";
            dispatch_data_mysql_sql(sql,request_data + offset,data_len - offset);
            break;
        }

    case COM_QUIT:
        {
            break;
        }

    default:
        break;
    }

    if(sql.length() > 1)
    {
        session->current_sql = init_sniffer_buf(sql.c_str());
        DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream_RequestQuery() [U]%s\t [S]%s\t [Q]%s\t",
                session->login_user?session->login_user->buf:"[]",
                session->login_with_schema?session->login_with_schema->buf:"[]",
                sql.c_str());

        session->op_end = sniffer_log_time_ms();
        sniffer_sql_log(session);
    }
}

static void dispatch_data_mysql_downstream_Handshake(sniffer_session *session,const char * payload,uint32_t payload_len)
{
    struct st_mysql * st = (struct st_mysql*)session->db_features;
    
    uint32_t offset = 0;
    uint8_t version = payload[offset];
    offset++;

    string temp = "";

    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream_Handshake() version %d",(int)version);

    if(0x0a == version)
    {
        //server version.[string<NULL>]
        temp = payload + offset;
        offset = offset + temp.length() + 1;

        //thread id
        offset = offset + 4;

        //auth-plugin-data-part-1 salt. 8
        offset = offset + 8;

        //filler 1.
        offset = offset + 1;

        //capability_flags_1, 2
        st->capabilities = payload[offset] + (payload[offset + 1] << 8);
        offset = offset + 2;

        //server character_set.
        offset = offset + 1;

        //status_flags ,2
        offset = offset + 2;

        //capability_flags_2[高两位], 2 
        st->capabilities = st->capabilities + ((payload[offset] + (payload[offset + 1] << 8)) << 16);
        offset = offset + 2;

        if(st->capabilities & CLIENT_PROTOCOL_41)
        {
            st->isProtocolV41 = true;
        }
    }
    else if(0x09 == version)
    {
        st->isProtocolV41 = false;
    }
}

static void dispatch_data_mysql_upstream_LoginRequest_V41(sniffer_session *session,const char * payload,uint32_t payload_len)
{
    uint32_t offset = 0;

    struct st_mysql * st = (struct st_mysql*)session->db_features;

    string _current_schema = "";
    string _current_user = "";

    memcpy(&st->capabilities,payload,4);
    offset = offset + 4;

    //Max packet len. 4
    //_max_packet_len = payload[offset] + (payload[offset + 1] << 8) + 
    //            (payload[offset + 2] << 16) + (payload[offset + 3] << 24);
    
    offset = offset + 4;

    //Charset 1
    //_charset = payload[offset];
    offset = offset + 1;

    //Unused 23
    offset = offset + 23;

    //USER_NAME Protocol::NullTerminatedString
    _current_user = (char*)payload + offset;
    offset = offset + _current_user.length() + 1;

    //Auth Response.
    if(st->capabilities&CLIENT_PLUGIN_AUTH_LENENCODENT_DATA)
    {
        uint16_t response_len = payload[offset];
        offset = offset + response_len + 1;
    }
    else
    {
        //Password_hash len.
        uint16_t password_hash_len = payload[offset];

        ///Dump_PasswordHash((unsigned char*)payload + offset + 1,password_hash_len);
        offset = offset + password_hash_len + 1;
    }

    //CLIENT_CONNECT_WITH_DB
    if(st->capabilities&CLIENT_CONNECT_WITH_DB)
    {
        _current_schema = (char*)payload + offset;
        offset = offset + _current_schema.length() + 1;
    }

    //Switch to ssl.
    if(st->capabilities&CLIENT_SSL)
    {
        WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream_LoginRequest() switch to %s","SSL");
        st->ssl = true;
    }

    //CLIENT_COMPRESS
    if(st->capabilities&CLIENT_COMPRESS)
    {
        WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream_LoginRequest() switch to %s","compressed");
        st->compressed = true;
    }
    else
    {
        st->compressed = false;
    }

    if(_current_schema.length() > 0)
    {
        session->login_with_schema = init_sniffer_buf(_current_schema.c_str());
    }

    if(_current_user.length() > 0)
    {
        session->login_user = init_sniffer_buf(_current_user.c_str());
    }

    //client_plugin_name string<NUL>
    if(st->capabilities & CLIENT_PLUGIN_AUTH)
    {
        string client_plugin_name = (char*)payload + offset;
        offset = offset + client_plugin_name.length() + 1;
    }

    //外带参数.
    if(st->capabilities & CLIENT_CONNECT_ATTRS)
    {
        uint16_t length_len = 0;
        uint32_t attrs_len = _mysql_lenenc(payload,offset,length_len);
        
        while (attrs_len > 0)
        {
            string key = "";
            string value = "";

            uint32_t key_len = _mysql_lenenc(payload,offset,length_len);
            key.append(payload + offset,key_len);
            offset = offset + key_len;
            attrs_len = attrs_len - length_len - key_len;

            uint32_t value_len = _mysql_lenenc(payload,offset,length_len);
            value.append(payload + offset,value_len);
            offset = offset + value_len;
            attrs_len = attrs_len - length_len - value_len;

            DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream_LoginRequest_V41() key %s,value %s",
                key.c_str(),value.c_str());
            
            if(string::npos != key.find("_os"))
            {
                session->os_info = init_sniffer_buf(value.c_str());
            }

            if(string::npos != key.find("os_user"))
            {
                //session->os_info = init_sniffer_buf(value.c_str());
            }

            if(string::npos != key.find("_client_name"))
            {

            }

            if(string::npos != key.find("_client_version"))
            {

            }
        }
    }
}

static void dispatch_data_mysql_upstream_LoginRequest_V320(sniffer_session *session,const char * payload,uint32_t payload_len)
{

}

static void dispatch_data_mysql_upstream_LoginRequest(sniffer_session *session,const char * payload,uint32_t payload_len)
{
    struct st_mysql * st = (struct st_mysql*)session->db_features;
    if(st)
    {
        st->query = false;
    }

    if(st->isProtocolV41)
    {
        dispatch_data_mysql_upstream_LoginRequest_V41(session,payload,payload_len);
    }
    else
    {
        dispatch_data_mysql_upstream_LoginRequest_V320(session,payload,payload_len);
    }
}

static void dispatch_data_mysql_upstream_AuthSwitchResponse(sniffer_session *session,const char * request_data,int data_len)
{
    struct st_mysql * st = (struct st_mysql*)session->db_features;
    if(st)
    {
        st->query = false;
    }

    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream_AuthSwitchResponse() len %d",data_len);
}

int dispath_data_mysql_downstream_err_packet(sniffer_session *session,const char * data,uint32_t data_len)
{
    uint32_t offset = 0;

    if(0xFF != (data[offset]&0xff))
    {
        return 0;
    }

    offset = offset + 1;

    //error code.
    session->err_code = 0;
    memcpy(&session->err_code,data + offset,2);
    offset = offset + 2;

    struct st_mysql * st = (struct st_mysql*)session->db_features;
    if(st)
    {
        /*
        if capabilities & CLIENT_PROTOCOL_41 {
            string[1]	sql_state_marker	# marker of the SQL state
            string[5]	sql_state	SQL state
        }
        */
        if(st->capabilities & CLIENT_PROTOCOL_41)
        {
            offset = offset + 6;
        }
    }

    //error msg.
    if(session->err_msg)
    {
        destroy_sniffer_buf(session->err_msg);
        session->err_msg = nullptr;
    }

    session->err_msg = init_sniffer_buf(data + offset,data_len - offset);

    INFO_LOG("sniffer_mysql.cpp:dispath_data_mysql_downstream_err_packet() error_code %d,error_msg %s",
            session->err_code,session->err_msg->buf);
    
    return 0;
}

int dispatch_data_mysql(sniffer_session *session,const char * data,uint32_t data_len)
{
    if(data_len <= 0)
    {
        ERROR_LOG("sniffer_mysql.cpp:dispatch_data_mysql() data_len %d",data_len);
        return 0;
    }

    DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql() from_upstream %d",session->from_upstream);

    if(session->from_upstream)
    {
        //下行流量.
        return dispatch_data_mysql_downstream(session,data,data_len);
    }
    else
    {
        //上行流量.
        return dispatch_data_mysql_upstream(session,data,data_len);
    }

    return 0;
}

//上行流量.
int dispatch_data_mysql_upstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    uint32_t _packet_len = 0;
    uint8_t _sequence_id = 0;

    _packet_len = (data[0]&0xff) + (data[1] << 8) + (data[2] << 16);
    _sequence_id = data[3];

    //需要的长度大于传入数据长度.
    if((_packet_len + MYSQL_HEAD_LEN) > data_len)
    {
        WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql() _packet_len %d,real_len %d,NEED_MORE.",
            _packet_len,data_len);
        return 1;
    }

    if(_sequence_id > 3)
    {
        ERROR_LOG("sniffer_mysql.cpp:dispatch_data_mysql() _sequence_id %d to_big.",_sequence_id);
    }

    session->err_code = 0;

    switch (_sequence_id)
    {
    case 0:
        {
            //Request Query
            INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream() type %s","[Request Query]");

            session->op_start = sniffer_log_time_ms();
            dispatch_data_mysql_upstream_RequestQuery(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
            break;
        }
    
    case 1:
        {
            //Login Request
            INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream() type %s","[Login Request]");

            dispatch_data_mysql_upstream_LoginRequest(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
            session->op_start = sniffer_log_time_ms();
            break;
        }

    case 3:
        {
            //Auth Switch Response
            INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream() type %s","[Auth Switch Response]");

            dispatch_data_mysql_upstream_AuthSwitchResponse(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
            break;
        }

    default:
        {
            ERROR_LOG("sniffer_mysql.cpp:dispatch_data_mysql_upstream() _sequence_id %d NOT_DEAL.",_sequence_id);
            break;
        }
    }

    return 0;
}

//下行流量.
int dispatch_data_mysql_downstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    uint32_t _packet_len = 0;
    uint8_t _sequence_id = 0;

    struct st_mysql * st = (struct st_mysql*)session->db_features;

    _packet_len = (data[0]&0xff) + (data[1] << 8) + (data[2] << 16);
    _sequence_id = data[3];

    DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() _packet_len %d,_sequence_id %d",_packet_len,_sequence_id);

    if(_packet_len <= 0)
    {
        return 1;
    }

    switch (_sequence_id)
    {
    case 0:
        {
            //Server Greeting
            INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Server Greeting]");

            dispatch_data_mysql_downstream_Handshake(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
            break;
        }

    case 1:
        {
            //Query Response.
            if(0xff == (data[4]&0xff))
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response] ERROR");
                dispath_data_mysql_downstream_err_packet(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
            }
            else
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response] OK");
                session->err_code = 0;
            }

            break;
        }

    case 2:
        {
            if(st->query)
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response......] OK");
            }
            else
            {
                //[Auth Switch Request] OR [Response OK]
                if(0xfe == (data[4]&0xff))
                {
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Auth Switch Request]");
                }
                else if(0xff == (data[4]&0xff))
                {
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[2_Response OK] ERROR");
                    
                    dispath_data_mysql_downstream_err_packet(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);

                    session->op_end  = sniffer_log_time_ms();
                    sniffer_session_log(session,true);
                }
                else
                {
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[2_Response OK] OK");
                    
                    session->err_code = 0;
                    session->op_end  = sniffer_log_time_ms();

                    sniffer_session_log(session,true);
                }
            }
            
            break;
        }

    case 4:
        {
            if(st->query)
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response......] OK");
            }
            else
            {
                //Response OK
                if(0xff == (data[4]&0xff))
                {
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[4_Response OK] ERROR");
                    dispath_data_mysql_downstream_err_packet(session,data + MYSQL_HEAD_LEN,data_len - MYSQL_HEAD_LEN);
                }
                else
                {
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[4_Response OK] OK");
                    session->err_code = 0;
                }

                session->op_end  = sniffer_log_time_ms();
                sniffer_session_log(session,true);
            }
            
            break;
        }
    
    default:
        {
            INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response......] OK");
            break;
        }
    }

    return 0;
}
