
#include <sniffer_mysql.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

int dispatch_data_mysql_parseHead(struct st_mysql *mysql,struct sniffer_buf *buf)
{
    mysql->packet_len = (buf->buf[0]&0xff) + ((buf->buf[1]&0xff) << 8) + ((buf->buf[2]&0xff) << 16);
    mysql->seq_number = (buf->buf[3]&0xff);

    return MYSQL_HEAD_LEN;
}

static uint32_t _mysql_lenenc(const char * data,uint32_t &offset,uint16_t &len_len)
{
    unsigned char flag = data[offset];
    uint32_t attrs_len = 0;

    if (flag <= 0xfb)
    {
		attrs_len = flag&0xff;
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
        attrs_len = (data[offset]&0xff) + ((data[offset + 1]&0xff) << 8) + ((data[offset + 2]&0xff) << 16);
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
        st->cmd_type = command_type;

        st->affect_rows = 0;
        st->columns_select = 0;
        st->columns_select_index = 0;

        if(!st->columns_select_type)
        {
            zfree(st->columns_select_type);
            st->columns_select_type = nullptr;
        }

        st->max_rowset = sniffer_cfg_max_rowset();
        st->rowsets = init_sniffer_buf(1024);

        reset_sniffer_buf(st->downstream_buf);
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

        ////sniffer_sql_log(session);
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

int dispatch_data_mysql_downstream_err_packet(sniffer_session *session,const char * data,uint32_t data_len)
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

    if(session->err_msg)
    {
        destroy_sniffer_buf(session->err_msg);
        session->err_msg = nullptr;
    }

    session->err_msg = init_sniffer_buf(data + offset,data_len - offset);

    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream_err_packet() error_code %d,error_msg %s",
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
    uint32_t offset = 0;

    struct st_mysql * st = (struct st_mysql*)session->db_features;
    cat_sniffer_buf(st->downstream_buf,data,data_len);

    do
    {
        if(len_sniffer_buf(st->downstream_buf) < MYSQL_HEAD_LEN)
        {
            WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() _packet_len %d NOT_MEET_MYSQL_HEAD",len_sniffer_buf(st->downstream_buf));
            break;
        }

        offset = dispatch_data_mysql_parseHead(st,st->downstream_buf);
        if(len_sniffer_buf(st->downstream_buf) < (MYSQL_HEAD_LEN + st->packet_len))
        {
            WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() _packet_len %d NOT_MEET_MYSQL_PACKET",len_sniffer_buf(st->downstream_buf));
            break;
        }

        DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() _packet_len %d,_sequence_id %d",st->packet_len,st->seq_number);

        if(st->query)
        {
            //Query Response. ERR_PACKET.
            if(0xff == (index_sniffer_buf(st->downstream_buf,offset)&0xff))
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response] ERROR");
                dispatch_data_mysql_downstream_err_packet(session,st->downstream_buf->buf + offset,len_sniffer_buf(st->downstream_buf) - offset);
                reset_sniffer_buf(st->downstream_buf);

                sniffer_sql_log(session);
            }
            else if(0xfe == (index_sniffer_buf(st->downstream_buf,offset)&0xff)) //EOF_PACKET.
            {
                //EOF 没有需要解析的内容，直接跳过。

                //判断是否是表头结束. 可能处于表头和表数据之间的EOF.
                if(len_sniffer_buf(st->downstream_buf) <= (7 + MYSQL_HEAD_LEN))
                {
                    reset_sniffer_buf(st->downstream_buf);
                    sniffer_sql_log(session);
                    break;
                }
                else
                {
                    rePosition_sniffer_buf(st->downstream_buf,(st->packet_len + offset));
                    continue;
                }
            }
            else if(0x00 == (index_sniffer_buf(st->downstream_buf,offset)&0xff))
            {
                INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Query Response] OK");
                session->err_code = 0;

                if(st->cmd_type == COM_STMT_PREPARE)
                {
                    offset++;
                    //xProxy_mysql_COM_STMT_PREPARE_Response(proxy_mysql,offset);
                    rePosition_sniffer_buf(st->downstream_buf,(st->packet_len + MYSQL_HEAD_LEN));
                    continue;
                }
                else
                {
                    if(st->cmd_type != COM_STMT_EXECUTE)
                    {
                        //非select语句:delete/insert/update/grant/create/drop...
                        st->affect_rows = dispatch_mysql_DDL_Reponse(st->downstream_buf,offset + 1);
                        reset_sniffer_buf(st->downstream_buf);

                        sniffer_sql_log(session);

                        break;
                    }
                }
            }

            //解析数据
            if(COM_FIELD_LIST == st->cmd_type)
            {
                //解析表头.
                st->affect_rows++;
                ///dispatch_mysql_ResultsetRow_ColumnDefinition(session);
            }
            else if(COM_STMT_PREPARE == st->cmd_type)
            {
                //返回num_params和num_columns 和解析表头结构一致.
            }
            else
            {
                //select_SQL.
                if(st->seq_number == 1)
                {
                    st->columns_select = (index_sniffer_buf(st->downstream_buf,offset)&0xff);
                    st->columns_select_index = st->columns_select;

                    st->columns_select_type = (uint16_t*)zmalloc(sizeof(uint16_t)*st->columns_select);
                    if(st->columns_select_type)
                    {
                        memset(st->columns_select_type,0,st->columns_select);
                    }

                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() columns_select %d",st->columns_select);
                }
                else
                {
                    if(st->columns_select_index <= 0)
                    {
                        if(st->cmd_type == COM_STMT_EXECUTE)
                        {
                            st->affect_rows++;
                            dispatch_mysql_ResultsetRow_Stmt(session);
                        }
                        else
                        {
                            //解析表数据.
                            st->affect_rows++;
                            dispatch_mysql_ResultsetRow(session);
                        }
                    }
                    else
                    {
                        //解析表头.
                        DEBUG_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() columns_select_index %d",st->columns_select - st->columns_select_index);
                        dispatch_mysql_ResultsetRow_ColumnDefinition(session,st->columns_select - st->columns_select_index);
                        st->columns_select_index = st->columns_select_index - 1;
                    }
                }
            }
        }
        else
        {
            switch (st->seq_number)
            {
            case 0:
                {
                    //Server Greeting
                    INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Server Greeting]");
                    dispatch_data_mysql_downstream_Handshake(session,st->downstream_buf->buf + offset,len_sniffer_buf(st->downstream_buf) - offset);
                    break;
                }

            case 2:
                {
                    //[Auth Switch Request] OR [Response OK]
                    if(0xfe == (index_sniffer_buf(st->downstream_buf,offset)&0xff))
                    {
                        INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[Auth Switch Request]");
                    }
                    else if(0xff == (index_sniffer_buf(st->downstream_buf,offset)&0xff))
                    {
                        INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[2_Response OK] ERROR");
                        
                        dispatch_data_mysql_downstream_err_packet(session,st->downstream_buf->buf + offset,len_sniffer_buf(st->downstream_buf) - offset);

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
                    
                    break;
                }

            case 4:
                {
                    //Response OK
                    if(0xff == (index_sniffer_buf(st->downstream_buf,offset)&0xff))
                    {
                        INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[4_Response OK] ERROR");
                        dispatch_data_mysql_downstream_err_packet(session,st->downstream_buf->buf + offset,len_sniffer_buf(st->downstream_buf) - offset);
                    }
                    else
                    {
                        INFO_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() type %s","[4_Response OK] OK");
                        session->err_code = 0;
                    }

                    session->op_end  = sniffer_log_time_ms();
                    sniffer_session_log(session,true);
                    
                    break;
                }
            }
        }

        //移动到下一个包.
        rePosition_sniffer_buf(st->downstream_buf,(st->packet_len + MYSQL_HEAD_LEN));
        if(len_sniffer_buf(st->downstream_buf) <= 0)
        {
            WARN_LOG("sniffer_mysql.cpp:dispatch_data_mysql_downstream() _packet_len %d EXIT",len_sniffer_buf(st->downstream_buf));
            break;
        }
    } while (1);

    return 0;
}

uint32_t dispatch_mysql_DDL_Reponse(struct sniffer_buf *buf,uint32_t offset)
{
    uint32_t attr_len = 0;
    uint16_t length_len = 0;
    attr_len = _mysql_lenenc(buf->buf,offset,length_len);

    INFO_LOG("sniffer_mysql.cpp:dispatch_mysql_DDL_Reponse() affect_rows %d",attr_len);

    return attr_len;
}

uint32_t dispatch_mysql_ResultsetRow(sniffer_session *session)
{
    uint32_t attrs_len = 0;
    uint16_t length_len = 0;
    uint32_t offset = MYSQL_HEAD_LEN;
    string rowset = "";

    struct st_mysql* mysql = (struct st_mysql*)session->db_features;
    struct sniffer_buf * buf = mysql->downstream_buf;

    if(mysql->max_rowset <= 0)
    {
        return 0;
    }

    while(offset < (mysql->packet_len + MYSQL_HEAD_LEN))
    {
        //依次按照字符串解析数据.NULL 为0xfb
        if(0xfb == (buf->buf[offset]&0xff))
        {
            DEBUG_LOG("sniffer_mysql.c:dispatch_mysql_ResultsetRow() value %s","NULL");
            offset++;

            rowset = rowset + "NULL";
            rowset = rowset + "||";
        }
        else
        {
            string value = "";
            attrs_len = _mysql_lenenc((const char *)buf->buf,offset,length_len);
            if(attrs_len >= 1)
            {
                value.append(buf->buf + offset,attrs_len);
            }
            else
            {
                value = "0";
            }

            DEBUG_LOG("sniffer_mysql.c:dispatch_mysql_ResultsetRow() value %s",value.c_str());
            offset = offset + attrs_len;

            rowset = rowset + value;
            rowset = rowset + "||";
        }
    }

    rowset = rowset.substr(0,rowset.length() - 2);
    DEBUG_LOG("sniffer_mysql.c:dispatch_mysql_ResultsetRow() rowset %s",rowset.c_str());

    //追加到结果集.
    cat_sniffer_buf(mysql->rowsets,";;");
    cat_sniffer_buf(mysql->rowsets,rowset.c_str(),rowset.length());
    mysql->max_rowset--;

    return 0;
}

uint32_t dispatch_mysql_ResultsetRow_Stmt(sniffer_session *session)
{
    uint32_t attrs_len = 0;
    uint16_t length_len = 0;
    uint32_t offset = MYSQL_HEAD_LEN;

    char *null_bitmaps = NULL;
    uint32_t null_bitmap_len = 0;
    uint32_t column_index = 0;
    uint8_t bitmap_byte = 0;
    uint8_t bitmap_bit = 0;

    string rowset = "";
    string value = "";

    struct st_mysql* mysql = (struct st_mysql*)session->db_features;
    struct sniffer_buf * buf = mysql->downstream_buf;

    if(mysql->max_rowset <= 0)
    {
        return 0;
    }

    //header 1
    //uint8_t header = buf->buf[offset]&0xff;
    offset = offset + 1;

    //null_bitmap.
    null_bitmap_len = (mysql->columns_select + 7 + 2)/8;
    null_bitmaps = (char*)zmalloc(sizeof(char)*null_bitmap_len);
    memcpy(null_bitmaps,buf->buf + offset,null_bitmap_len);

    offset = offset + null_bitmap_len;

    for(column_index = 0; column_index < mysql->columns_select;column_index++)
    {
        bitmap_byte = (column_index + 2)/8;
        bitmap_bit = (column_index + 2)%8;
        
        //判断该列是否是NULL.
        if(null_bitmaps[bitmap_byte] & (1 << bitmap_bit))
        {
            DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,NULL",column_index);

            rowset = rowset + "NULL";
            rowset = rowset + "||";
            continue;
        }

        //根据数据类型获取该列数据.
        switch (mysql->columns_select_type[column_index])
        {
            case MYSQL_TYPE_STRING:
            case MYSQL_TYPE_VAR_STRING:
            case MYSQL_TYPE_VARCHAR:
            {
                length_len = 0;
                attrs_len = _mysql_lenenc(buf->buf,offset,length_len);
                if(attrs_len > 0)
                {
                    value.append(buf->buf + offset,attrs_len);
                }
                else
                {
                    value = "0";
                }

                offset = offset + attrs_len;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%s",column_index,value.c_str());
                
                rowset = rowset + value;
                rowset = rowset + "||";
                break;
            }

            case MYSQL_TYPE_LONG:
            case MYSQL_TYPE_INT24:
            {
                uint32_t temp = 0;
                memcpy(&temp,buf->buf + offset,4);

                offset = offset + 4;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%d",column_index,temp);
                
                rowset = rowset + to_string(temp);
                rowset = rowset + "||";
                break;
            }
            
            case MYSQL_TYPE_LONGLONG:
            {
                uint64_t temp = 0;
                memcpy(&temp,buf->buf + offset,8);
                
                offset = offset + 8;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%d",column_index,temp);

                rowset = rowset + to_string(temp);
                rowset = rowset + "||";
                break;
            }

            case MYSQL_TYPE_SHORT:
            case MYSQL_TYPE_YEAR:
            {
                uint16_t temp = 0;
                memcpy(&temp,buf->buf + offset,2);
                
                offset = offset + 2;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%d",column_index,temp);

                rowset = rowset + to_string(temp);
                rowset = rowset + "||";

                break;
            }

            case MYSQL_TYPE_TINY:
            {
                uint8_t temp = 0;
                memcpy(&temp,buf->buf + offset,1);
                
                offset = offset + 1;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%d",column_index,temp);

                rowset = rowset + to_string(temp);
                rowset = rowset + "||";
                break;
            }

            case MYSQL_TYPE_DOUBLE:
            {
                char temp[9] = {0};
                memcpy(&temp,buf->buf + offset,8);
                
                offset = offset + 8;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%s",column_index,temp);

                rowset = rowset + temp;
                rowset = rowset + "||";

                break;
            }

            case MYSQL_TYPE_FLOAT:
            {
                char temp[5] = {0};
                memcpy(&temp,buf->buf + offset,4);
                
                offset = offset + 4;
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%s",column_index,temp);

                rowset = rowset + temp;
                rowset = rowset + "||";

                break;
            }

            case MYSQL_TYPE_TIME:
            {
                DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() index %d,%s",column_index,"N_DEAL");
                
                rowset = rowset + "N_DEAL||";
                offset = offset + (index_sniffer_buf(mysql->downstream_buf,offset)&0xff);
                break;
            }

            case MYSQL_TYPE_DATE:
            case MYSQL_TYPE_DATETIME:
            case MYSQL_TYPE_TIMESTAMP:
            {
                rowset = rowset + "N_DEAL||";
                offset = offset + (index_sniffer_buf(mysql->downstream_buf,offset)&0xff);

                break;
            }

            default:
            {
                break;
            }
        }
    }

    zfree(null_bitmaps);

    rowset = rowset.substr(0,rowset.length() - 2);
    DEBUG_LOG("sniffer_mysql.cpp:dispatch_mysql_ResultsetRow_Stmt() rowset %s",rowset.c_str());

    //追加到结果集.
    cat_sniffer_buf(mysql->rowsets,";;");
    cat_sniffer_buf(mysql->rowsets,rowset.c_str(),rowset.length());
    mysql->max_rowset--;

    return 0;
}

uint32_t dispatch_mysql_ResultsetRow_ColumnDefinition(sniffer_session *session,uint32_t index)
{
    uint32_t attrs_len = 0;
    uint16_t length_len = 0;
    uint32_t offset = MYSQL_HEAD_LEN;
    string tmp = "";
    string name = "";

    struct st_mysql* mysql = (struct st_mysql*)session->db_features;
    struct sniffer_buf * buf = mysql->downstream_buf;

    if(!mysql->isProtocolV41)
    {
        DEBUG_LOG("xProxy_db_mysql.c:dispatch_mysql_ResultsetRow_ColumnDefinition() %s NOT_DEAL","Protocol::ColumnDefinition320");
        return 0;
    }

    /*
        Protocol::ColumnDefinition41

        需要解析的数据依次为 catalog/schema/table/org_table/name/org_name,数据格式为string<lenenc>
    */
    //1-catalog
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        tmp.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //2-schema
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        tmp.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //3-table
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        tmp.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //4-org_table
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        tmp.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //5-name
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        name.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //6-org_name
    attrs_len = _mysql_lenenc((const char*)buf->buf,offset,length_len);
    if(attrs_len > 0)
    {
        tmp.append(buf->buf + offset,attrs_len);
    }
    offset = offset + attrs_len;

    //length of fixed length fields [0x0c]
    offset = offset + 1;

    //character_set 2
    offset = offset + 2;

    //column_length 4
    offset = offset + 4;

    //type  1
    uint8_t data_type = (buf->buf[offset]&0xff);
    offset = offset + 1;

    mysql->columns_select_type[index] = data_type;

    INFO_LOG("xProxy_db_mysql.c:dispatch_mysql_ResultsetRow_ColumnDefinition() name %s,data_type %d",name.c_str(),data_type);

    if(index == (mysql->columns_select - 1))
    {
        cat_sniffer_buf(mysql->rowsets,name.c_str(),name.length());
    }
    else
    {
        cat_sniffer_buf(mysql->rowsets,name.c_str(),name.length());
        cat_sniffer_buf(mysql->rowsets,"||");
    }

    return 0;
}
