
#include <sniffer_oracle.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

#include <ctype.h>
#include <arpa/inet.h>

const char * G_TNS_TYPE_NAME[TNS_TYPE_MAX] = {
    "Unkown",
    "Connect",
    "Accept",
    "ACK",
    "Refuse",
    "Redirect",
    "Data",
    "NULL",
    "----",
    "Abort",
    "----",
    "Resend",
    "Marker",
    "Attention",
    "Control"
};

const char * G_ROWID_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void xProxy_db_oracle_ROWID(struct xProxy_buf * src,struct xProxy_buf*str,int mode)
{

}

static uint32_t _ZPow(uint32_t cnt)
{
    uint32_t sum = 1;
    uint32_t index = 0;

    while(index < cnt)
    {
        sum = sum*100;
        index++;
    }

    return sum;
}

static uint8_t _IsPrintEnglish(char c)
{
    //大写字母 A～Z; 小写字母 a～z.
    if((0x41 <= c && c <= 0x5a) || (0x61 <= c && c <= 0x7a))
    {
        return 1;
    }

    return 0;
}

static uint8_t _IsOracleBeginStr(const char* str)
{
    if(0 == strncasecmp(str,"select",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"update",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"insert",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"delete",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"create",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"drop",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"alter",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"grant",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"begin",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"declare",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"revoke",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"begin",5))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"call",4))
    {
        return 1;
    }
    else if(0 == strncasecmp(str,"commit",6))
    {
        return 1;
    }

    return 0;
}

uint32_t xProxy_oracle_ParseHead(struct st_oracle * oracle,struct sniffer_buf * buf)
{
    memset(&oracle->_tns_header,0,sizeof(struct tns_header));
    memcpy(&oracle->_tns_header,buf->buf,ORACLE_HEAD_LEN);

    //网络字节序转为主机字节序.
    oracle->_tns_header.packet_len = ntohs(oracle->_tns_header.packet_len);

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_ParseHead() packet_len %d,packet_type %d",
            oracle->_tns_header.packet_len,oracle->_tns_header.packet_type);

    return ORACLE_HEAD_LEN;
}

int dispatch_data_oracle(sniffer_session *session,const char * data,uint32_t data_len)
{
    if(session->from_upstream)
    {
        return xProxy_oracle_downstream(session,data,data_len);
    }

    return xProxy_oracle_upstream(session,data,data_len);;
}

uint32_t xProxy_oracle_upstream(struct sniffer_session *session, const char * payload,uint32_t payload_len)
{
    uint32_t offset = 0;
    struct st_oracle * proxy_oracle = (struct st_oracle *)session->db_features;
    if(NULL == proxy_oracle)
    {
        return payload_len;
    }

    proxy_oracle->from_upstream = 0;
    cat_sniffer_buf(proxy_oracle->upstream_buf,(const char*)payload,payload_len);
    if(len_sniffer_buf(proxy_oracle->upstream_buf) < ORACLE_HEAD_LEN)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_upstream() buf_len %d NOT_MEET_ORACLE_HEAD",len_sniffer_buf(proxy_oracle->upstream_buf));
        return payload_len;
    }

    offset = xProxy_oracle_ParseHead(proxy_oracle,proxy_oracle->upstream_buf);
    if(len_sniffer_buf(proxy_oracle->upstream_buf) < proxy_oracle->_tns_header.packet_len)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_upstream() buf_len %d NOT_MEET_ORACLE_PACKET",len_sniffer_buf(proxy_oracle->upstream_buf));
        return payload_len;
    }

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_upstream() packet_type %s",G_TNS_TYPE_NAME[proxy_oracle->_tns_header.packet_type]);

    //开始时间
    session->op_start = sniffer_log_time_ms();
    proxy_oracle->max_rowset = sniffer_cfg_max_rowset();
    proxy_oracle->fetch_a_row = 0;

    switch (proxy_oracle->_tns_header.packet_type)
    {
        case TNS_TYPE_CONNECT:
        {
            xProxy_oracle_TNS_Connect(session,offset);
            break;
        }

        case TNS_TYPE_DATA:
        {
            xProxy_oracle_TNS_Data(session,offset);
            break;
        }

        case TNS_TYPE_MARKER:
        {
            xProxy_oracle_TNS_Marker(session,offset);
            break;
        }

        default:
        {
            break;
        }
    }

    //重置buf.
    reset_sniffer_buf(proxy_oracle->upstream_buf);

    return 0;
}

uint32_t xProxy_oracle_downstream(struct sniffer_session *session, const char * payload,uint32_t payload_len)
{
    uint32_t offset = 0;
    struct st_oracle * proxy_oracle = (struct st_oracle *)session->db_features;
    if(NULL == proxy_oracle)
    {
        return payload_len;
    }

    proxy_oracle->from_upstream = 1;
    cat_sniffer_buf(proxy_oracle->downstream_buf,(const char*)payload,payload_len);
    if(len_sniffer_buf(proxy_oracle->downstream_buf) < ORACLE_HEAD_LEN)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_downstream() buf_len %d NOT_MEET_ORACLE_HEAD",len_sniffer_buf(proxy_oracle->downstream_buf));
        return payload_len;
    }

    offset = xProxy_oracle_ParseHead(proxy_oracle,proxy_oracle->downstream_buf);
    if(len_sniffer_buf(proxy_oracle->downstream_buf) < proxy_oracle->_tns_header.packet_len)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_downstream() buf_len %d NOT_MEET_ORACLE_PACKET",len_sniffer_buf(proxy_oracle->downstream_buf));
        return payload_len;
    }

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_downstream() packet_type %s",G_TNS_TYPE_NAME[proxy_oracle->_tns_header.packet_type]);
    session->op_end = sniffer_log_time_ms();
    switch (proxy_oracle->_tns_header.packet_type)
    {
        case TNS_TYPE_REDIRECT:
        {
            xProxy_oracle_TNS_Redirect(session,offset);
            break;
        }

        case TNS_TYPE_ACCEPT:
        {
            xProxy_oracle_TNS_Accept(session,offset);
            break;
        }

        case TNS_TYPE_DATA:
        {
            xProxy_oracle_TNS_Data(session,offset);
            break;
        }

        case TNS_TYPE_RESEND:
        {
            xProxy_oracle_TNS_Resend(session,offset);
            break;
        }

        case TNS_TYPE_REFUSE:
        {
            //SID错误时返回信息.
            xProxy_oracle_TNS_Refuse(session,offset);
            break;
        }

        case TNS_TYPE_MARKER:
        {
            xProxy_oracle_TNS_Marker(session,offset);
            break;
        }

        default:
        {
            break;
        }
    }

    //重置buf.
    reset_sniffer_buf(proxy_oracle->downstream_buf);

    return 0;
}

void xProxy_oracle_TNS_Connect(struct sniffer_session *session,uint32_t offset)
{
    /*
        格式
        Service Name:
            (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=172.16.0.64)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=D:\Program Files\ABC.exe)(HOST=aaa)(USER=xxx))))
        SID:
            (DESCRIPTION=(CONNECT_DATA=(SID=orcl)(CID=(PROGRAM=SQL Developer)(HOST=__jdbc__)(USER=xxx)))(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.56.201)(PORT=1521)))
    */
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    string connect_data = "";
    string tmp = "";
    string _current_sid = "";

    size_t start_pos = string::npos;
    size_t stop_pos = string::npos;

    struct tns_connect connect;
    uint32_t connect_len = sizeof(struct tns_connect);

    struct sniffer_buf * buf = oracle->upstream_buf;

    memset(&connect,0,connect_len);
    memcpy(&connect,buf->buf + offset,connect_len);

    //网络字节序转为主机字节序.
    connect.connect_data_len = ntohs(connect.connect_data_len);
    connect.connect_data_pos = ntohs(connect.connect_data_pos);

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Connect() connect_data pos %d len %d",
            connect.connect_data_pos,connect.connect_data_len);

    for(uint32_t i = 0; i < connect.connect_data_len; i++)
    {
        connect_data.push_back(index_sniffer_buf(buf,connect.connect_data_pos + i));
    }

    tmp = connect_data;
    transform(tmp.begin(), tmp.end(), tmp.begin(), ::tolower);
    
    start_pos = tmp.find("sid=");
    if(string::npos != start_pos)
    {
        stop_pos = tmp.find_first_of(")",start_pos);
        if(string::npos != stop_pos)
        {
            _current_sid = connect_data.substr(start_pos + 4,stop_pos - start_pos - 4);
            INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Connect() connect_data SID %s",_current_sid.c_str());
        }
    }

    start_pos = tmp.find("service_name=");
    if(string::npos != start_pos)
    {
        stop_pos = tmp.find_first_of(")",start_pos);
        if(string::npos != stop_pos)
        {
            _current_sid = connect_data.substr(start_pos + 13,stop_pos - start_pos - 13);
            INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Connect() connect_data Service_Name %s",_current_sid.c_str());
        }
    }

    //PROGRAM
    start_pos = tmp.find("program=");
    if(string::npos != start_pos)
    {
        stop_pos = tmp.find_first_of(")",start_pos);
        if(string::npos != stop_pos)
        {
            string temp = connect_data.substr(start_pos + 8,stop_pos - start_pos - 8);
            INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Connect() connect_data PROGRAM %s",temp.c_str());

            session->client_info = init_sniffer_buf(temp.c_str());
        }
    }

    //USER
    start_pos = tmp.find("user=");
    if(string::npos != start_pos)
    {
        stop_pos = tmp.find_first_of(")",start_pos);
        if(string::npos != stop_pos)
        {
            string temp = connect_data.substr(start_pos + 5,stop_pos - start_pos - 5);
            INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Connect() connect_data USER %s",temp.c_str());

            session->os_user = init_sniffer_buf(temp.c_str());
        }
    }

    if(_current_sid.length() > 0)
    {
        session->login_with_schema = init_sniffer_buf(_current_sid.c_str(),_current_sid.length());
    }
}

void xProxy_oracle_TNS_Accept(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Accept");
}

void xProxy_oracle_TNS_Redirect(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Redirect");
}

void xProxy_oracle_TNS_Resend(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Resend");
}

//oracle sid写错.
void xProxy_oracle_TNS_Refuse(struct sniffer_session * session,uint32_t offset)
{
    /*
        数据如下格式:
        (DESCRIPTION=(TMP=)(VSNNUM=186647552)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))
    */
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    uint8_t refuse_reason_user = 0;
    uint8_t refuse_reason_system = 0;
    uint16_t refuse_data_length = 0;

    struct sniffer_buf * err_msg = NULL;
    struct sniffer_buf * buf = oracle->downstream_buf;

    //user 0x01
    refuse_reason_user = index_sniffer_buf(buf,offset);
    offset = offset + 1;
   
    //system 0x01
    refuse_reason_system = index_sniffer_buf(buf,offset);
    offset = offset + 1;

    //data_length 0x02 
    refuse_data_length = (index_sniffer_buf(buf,offset) << 8) + index_sniffer_buf(buf,offset + 1);
    offset = offset + 2;

    err_msg = init_sniffer_buf(refuse_data_length + 1);

    cat_sniffer_buf(err_msg,buf->buf + offset,refuse_data_length);

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Refuse() user 0x%02x, system 0x%02x, msg %s",
            refuse_reason_user,refuse_reason_system,err_msg->buf);

    destroy_sniffer_buf(err_msg);
    err_msg = NULL;
}

void xProxy_oracle_TNS_Marker(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Marker() %s Marker",
        oracle->from_upstream?"Response":"Request");
}

void xProxy_oracle_TNS_Data_0x01(struct sniffer_session * session,uint32_t offset)
{
    /*  
            Set Protocol具体协议
        Client --> Server:
            #Data flag
            #Data id
            #Accepted Versions ..... 0x00
            #Client Platform  ...... 0x00

        Server --> Client: 
            #Data flag
            #Data id
            #Versions ... 0x00
            #Server Banner  ...... 0x00
            #Data
    */
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    uint8_t from_upstream = oracle->from_upstream;
    struct sniffer_buf * buf = from_upstream?oracle->downstream_buf:oracle->upstream_buf;
    struct sniffer_buf * banner = init_sniffer_buf(128);

    //跨过Versions字段.
    while(0x00 != index_sniffer_buf(buf,offset))
    {
        offset++;
    }

    //跳过0x00.
    offset++;

    //找到Client Platform/Server Banner.
    while (0x00 != index_sniffer_buf(buf,offset))
    {
        pushback_sniffer_buf(banner,index_sniffer_buf(buf,offset));
        offset++;
    }
    
    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x01() %s",banner->buf);

    destroy_sniffer_buf(banner);
    banner = NULL;
}

void xProxy_oracle_TNS_Data_0x02(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Data_0x02");
}

void xProxy_oracle_TNS_Data_0x03(struct sniffer_session * session,uint32_t offset)
{
    /*
        0x03包
        Client -> Server:
            #Data flag [0x00 0x00]
            #Data id   [0x03]
            #Call id
            #Data ......
    */
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    uint16_t callID = (index_sniffer_buf(oracle->upstream_buf,offset)&0xff);
    offset = offset + 1;

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03() callID 0x%02x",callID);
    if(0 == oracle->from_upstream)
    {
        oracle->callID_query = callID;
    }

    switch (callID)
    {
        //Get the session key.
        case 0x76:
        {
            xProxy_oracle_TNS_Data_0x03_0x76(session,offset);
            break;
        }

        //Generic authentication call.
        case 0x73:
        {
            xProxy_oracle_TNS_Data_0x03_0x73(session,offset);
            break;
        }

        //SQL || SQL Prepare.
        case 0x5e:
        {
            xProxy_oracle_TNS_Data_0x03_0x5e(session,offset);
            break;
        }

        //SQL Prepare Execute and Fetch.
        case 0x4e:
        {
            xProxy_oracle_TNS_Data_0x03_0x4e(session,offset);
            break;
        }

        /*
            Fetch a row.
            返回数据函数
                >结束标记
                    xProxy_oracle_TNS_Data_0x04
                >有数据+结束标记
                    xProxy_oracle_TNS_Data_0x06.
        */
        case 0x05:
        {
            oracle->fetch_a_row = 1;
            xProxy_oracle_TNS_Data_0x03_0x05(session,offset);
            break;
        }

        //Get Oracle version-date string in new format.
        case 0x3b:
        {
            xProxy_oracle_TNS_Data_0x03_0x3b(session,offset);
            break;
        }

        //Commit.
        case 0x0e:
        {
            xProxy_oracle_TNS_Data_0x03_0x0e(session,offset);
            break;
        }

        default:
        {
            break;
        }
    }
}

/*
    用户名密码错误\SQL语句错误\Fetch a row时，返回错误信息/结束标志.
*/
void xProxy_oracle_TNS_Data_0x04(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->downstream_buf;
    struct sniffer_buf *data = init_sniffer_buf(32);
    string err_code = "";

    //找到ORA-开始的字符串.前面是长度.
    uint16_t data_len = 0x00;
    while((offset + 3) < len_sniffer_buf(buf))
    {
        if('O' == index_sniffer_buf(buf,offset + 1) && 
            'R' == index_sniffer_buf(buf,offset + 2) &&
            'A' == index_sniffer_buf(buf,offset + 3))
        {
            break;
        }

        offset++;
    }

    data_len = index_sniffer_buf(buf,offset);
    offset = offset + 1;

    cat_sniffer_buf(data,(buf->buf + offset),data_len);

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x04() offset %d,data %s",offset - 1,(data->buf));
    err_code = data->buf;

    err_code = err_code.substr(4);
    err_code = err_code.substr(0,err_code.find(":"));

    if(0x03 == oracle->dataID_query && 0x73 == oracle->callID_query)
    {
        //登录失败.
        session->err_code = atol(err_code.c_str());
        session->err_msg = init_sniffer_buf(data->buf,data_len);
        sniffer_session_log(session,true);
    }
    else if(0x03 == oracle->dataID_query && 0x5e == oracle->callID_query)
    {
        //SQL语句执行失败.
        session->err_code = atol(err_code.c_str());
        session->err_msg = init_sniffer_buf(data->buf,data_len);
        sniffer_sql_log(session);
    }

    destroy_sniffer_buf(data);
    data = NULL;
}

/*
    Fetch a row的数据加上 xProxy_oracle_TNS_Data_0x04.
*/
void xProxy_oracle_TNS_Data_0x06(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->downstream_buf;

    /*
        包括两部分数据:
            >select返回数据
            >ORA-01403
    */

    offset = offset + 1;

    if(0x00 != index_sniffer_buf(buf,offset))
    {
        DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x06() Have Data %s","");

        offset = offset + 0x30;
        offset = xProxy_oracle_TNS_Data_0x10_DATA(session,offset);
    }
}

//create user/grant to/revoke from/create table/insert into/update/delete 返回信息.
void xProxy_oracle_TNS_Data_0x08(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Data_0x08");
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    if(0x03 != oracle->dataID_query)
    {
        DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x08() NOT_DEAL dataID 0x%02x",oracle->dataID_query);
        return;
    }

    if(0x76 == oracle->callID_query)
    {

    }
    else if(0x73 == oracle->callID_query)
    {
        //登录成功.
        session->err_code = 0;
        sniffer_session_log(session,true);
    }
    else if(0x3b == oracle->callID_query)
    {

    }
    else if(0x5e == oracle->callID_query)
    {
        //SQL语句成功.
        session->err_code = 0;
        
        //结果集信息. update/insert/delete的影响行数暂未解析.
        oracle->affect_rows = 1;
        oracle->select_body = NULL;

        sniffer_sql_log(session);
    }
}

void xProxy_oracle_TNS_Data_0x09(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Data_0x09");
}

//Decribe Information. select返回结果集.
void xProxy_oracle_TNS_Data_0x10(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->downstream_buf;

    /*
        以下计算来自总结，无参考文档.
    */

    //sqlplus系统自带客户端工具、OCI类客户端.
    if(0x17 == index_sniffer_buf(buf,offset) && 
        0x00 == index_sniffer_buf(buf,offset + 1) && 
        0x00 == index_sniffer_buf(buf,offset + 2) &&
        0x00 == index_sniffer_buf(buf,offset + 3))
    {
        return xProxy_oracle_TNS_Data_0x10_1(session,offset);
    }
    //JDBC类工具.
    else if(0x17 == index_sniffer_buf(buf,offset))
    {
        return xProxy_oracle_TNS_Data_0x10_2(session,offset);
    }
}

void xProxy_oracle_TNS_Data_0x10_1(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->downstream_buf;
    uint32_t columns_pos = 0;
    uint32_t columns = 0;
    uint32_t column_index = 0;

    uint8_t column_name_type = 0;
    uint32_t column_name_len = 0;
    struct sniffer_buf * column_name = NULL;

    /*
        以下计算来自总结，无参考文档.
    */
   
    /*
        STEP-1:解析列数目.
    */

    columns_pos = 0x17;

    //Fixed{}.
    columns_pos = columns_pos + 0x08;
    offset = offset + columns_pos;

    //以次四个字节->select出的列数目. oracle最大限制1000.
    columns = (index_sniffer_buf(buf,offset)&0xff);
    columns += ((index_sniffer_buf(buf,offset + 1)&0xff) << 8);
    columns += ((index_sniffer_buf(buf,offset + 2)&0xff) << 16);

    offset = offset + 4;
    
    if(columns_pos <= 0)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_1() columns_pos %",columns_pos);
        return;
    }

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_1() select_columns %d",columns);

    oracle->columns_select_type = (uint16_t*)zmalloc(columns*sizeof(uint16_t));
    oracle->columns_select = columns;

    //跳过标记. 0x51
    offset = offset + 1;
    /*
        STEP-2:解析列名称以及数据类型.
    */
    for(column_index = 0;column_index < columns; column_index++)
    {
        //固定.
        offset = offset + 1;

        //数据类型.
        column_name_type = (index_sniffer_buf(buf,offset)&0xff);
        offset = offset + 1;

        //固定.
        offset = offset + 45;

        //一子节列名称长度. oracle最大列长度30.
        column_name_len = (index_sniffer_buf(buf,offset)&0xff);
        offset = offset + 1;

        //列名称.
        column_name = init_sniffer_buf(column_name_len + 1);
        cat_sniffer_buf(column_name,buf->buf + offset,column_name_len);

        offset = offset + column_name_len;

        //固定.
        offset = offset + 14;

        INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_1() index %d,type %d,name %s",
                column_index,column_name_type,(column_name->buf));
        
        destroy_sniffer_buf(column_name);
        column_name = NULL;

        oracle->columns_select_type[column_index] = column_name_type;
    }

    /*
        STEP-3:解析实际数据.{可能是没有结果集的情况}
    */
    offset = offset + 0x52;
    if(offset > len_sniffer_buf(buf))
    {

    }
    else
    {
        offset = xProxy_oracle_TNS_Data_0x10_DATA(session,offset);
    }

    /*
        STEP-4:直到ORA-01403: nodata found. 该结束标志可能存在于xProxy_oracle_TNS_Data_0x06中.
    */
}

void xProxy_oracle_TNS_Data_0x10_2(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->downstream_buf;
    uint32_t columns_pos = 0;
    uint32_t columns = 0;
    uint8_t  columns_len = 0;
    uint32_t column_index = 0;

    uint8_t column_name_type = 0;
    uint32_t column_name_len = 0;
    struct sniffer_buf * column_name = NULL;

    /*
        以下计算来自总结，无参考文档.
    */
   
    columns_pos = 0x17;

    //Fixed{}.
    columns_pos = columns_pos + 0x03;
    offset = offset + columns_pos;

    columns_len = index_sniffer_buf(buf,offset)&0xff;
    if(columns_len > 0x04)
    {
        offset = offset + 1;
        columns_len = index_sniffer_buf(buf,offset)&0xff;
    }
        
    offset = offset + 1;

    while(columns_len)
    {
        if(1 == columns_len)
        {
            columns = columns + (index_sniffer_buf(buf,offset)&0xff);
        }
        else if(2 == columns_len)
        {
            columns = columns + ((index_sniffer_buf(buf,offset)&0xff) << 8);
        }
        else if(3 == columns_len)
        {
            columns = columns + ((index_sniffer_buf(buf,offset)&0xff) << 16);
        }
            
        columns_len--;
        offset = offset + 1;
    }

    if(columns_pos <= 0)
    {
        WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_2() columns_pos %",columns_pos);
        return;
    }

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_2() select_columns %d",columns);

    oracle->columns_select_type = (uint16_t*)zmalloc(sizeof(uint16_t)*columns);
    oracle->columns_select = columns;

    //跳过标记. 0x51
    offset = offset + 1;
    /*
        STEP-2:解析列名称以及数据类型.
    */
    for(column_index = 0;column_index < columns; column_index++)
    {
        if(column_index > 0)
        {
            //jdbc数据类型不同.
            offset = offset + 3;
            if(0x00 == index_sniffer_buf(buf,offset))
            {
                offset = offset + 1;
            }
        }

        column_name_type = (index_sniffer_buf(buf,offset)&0xff);

        while(offset < len_sniffer_buf(buf))
        {
            column_name_len = (index_sniffer_buf(buf,offset)&0xff);
            if(column_name_len <= 30 &&
                (index_sniffer_buf(buf,offset - 1) == index_sniffer_buf(buf,offset)) &&
                isprint(index_sniffer_buf(buf,offset + 1)))
            {
                break;
            }

            offset = offset + 1;
        }

        //一字节长度.
        offset = offset + 1;

        column_name = init_sniffer_buf(column_name_len + 1);
        cat_sniffer_buf(column_name,(buf->buf + offset),column_name_len);
        offset = offset + column_name_len;

        while(index_sniffer_buf(buf,offset) == 0x00)
        {
            offset = offset + 1;
        }

        INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_2() index %d,type %d,len %d,name %s",
                column_index,column_name_type,column_name_len,(column_name->buf));
        
        destroy_sniffer_buf(column_name);
        column_name = NULL;

        oracle->columns_select_type[column_index] = column_name_type;
    }

    /*
        STEP-3:解析实际数据.
    */
    while(offset < len_sniffer_buf(buf))
    {
        if(0x07 == index_sniffer_buf(buf,offset) &&
            0x00 == index_sniffer_buf(buf,offset - 1) && 
            0x00 == index_sniffer_buf(buf,offset - 2) &&
            0x00 == index_sniffer_buf(buf,offset - 3))
        {
            break;
        }

        offset = offset + 1;
    }

    if(offset > len_sniffer_buf(buf))
    {

    }
    else
    {
        offset = xProxy_oracle_TNS_Data_0x10_DATA(session,offset);
    }

    /*
        STEP-4:直到ORA-01403: nodata found. 该结束标志可能存在于xProxy_oracle_TNS_Data_0x06中.
    */
}

uint32_t xProxy_oracle_TNS_Data_0x10_DATA(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf *buf = oracle->downstream_buf;
    uint32_t show_columns = 0;

    struct sniffer_buf * data_stream = NULL;
    uint32_t data_stream_len = 0;
    uint32_t column_index = 0;
    struct sniffer_buf * column_string = NULL;

    while(offset < len_sniffer_buf(buf))
    {
        /*
            每一行的行头.
        */
        if(0x07 != index_sniffer_buf(buf,offset))
        {
            offset = offset + 4;
            if(0x07 != index_sniffer_buf(buf,offset))
            {
                WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() NOT_ROWSET %s","");
                return offset;
            }
        }
        
        //0x07
        offset = offset + 1;
    
        //select_A_Star(*)时返回的数据.
        if(0x2c == index_sniffer_buf(buf,offset + 1) && 
            (0x00 == index_sniffer_buf(buf,offset + 2) || 0x01 == index_sniffer_buf(buf,offset + 2) || 0x02 == index_sniffer_buf(buf,offset + 2)))
        {
            offset = offset + 3;

            show_columns = (index_sniffer_buf(buf,offset)&0xff);
            offset = offset + 1;
            WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() a HAVE_SELECT_COLUMNS %d",show_columns);
        }
        else if(0x2c == index_sniffer_buf(buf,offset + 2) &&
            (0x00 == index_sniffer_buf(buf,offset + 3) || 0x01 == index_sniffer_buf(buf,offset + 3) || 0x02 == index_sniffer_buf(buf,offset + 3)))
        {
            offset = offset + 4;

            show_columns = (index_sniffer_buf(buf,offset)&0xff);
            offset = offset + 1;
            WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() b HAVE_SELECT_COLUMNS %d",show_columns);
        }
        else //select 指定列名称时返回的数据.
        {
            //直接给出数据.
            WARN_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() NO_HAVE_SELECT_COLUMNS %d",oracle->columns_select);
        }

        /*
            每一行的列数据.
        */
        column_index = 0;
        while(column_index < oracle->columns_select)
        {
            data_stream_len = index_sniffer_buf(buf,offset)&0xff;
            offset = offset + 1;

            INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() column_index %d,data_pre 0x%02x",
                        column_index,data_stream_len);
            
            if(0x00 == data_stream_len)
            {
                INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() column_index %d,column_data_string %s",
                        column_index,"(null)");
                
                column_index++;
                continue;
            }
            else if(0xff == data_stream_len)
            {
                INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() column_index %d,column_data_string %s",
                        column_index,"(null)");
                column_index++;
                continue;
            }
            else if(0xfe == data_stream_len)
            {
                if(0x01 == (index_sniffer_buf(buf,offset + 1)&0xff) || 0x02 == (index_sniffer_buf(buf,offset + 1)&0xff))
                {
                    data_stream_len = index_sniffer_buf(buf,offset)&0xff;
                    offset = offset + 1;

                    data_stream_len =  data_stream_len + (index_sniffer_buf(buf,offset)&0xff)*256;
                    offset = offset + 1;

                    //Magic...
                    data_stream_len = data_stream_len + 1;
                }
                else
                {
                    data_stream_len = index_sniffer_buf(buf,offset)&0xff;
                    offset = offset + 1;
                }
            }
            
            data_stream = init_sniffer_buf(data_stream_len);

            cat_sniffer_buf(data_stream,(buf->buf + offset),data_stream_len);
            offset = offset + data_stream_len;

            column_string = init_sniffer_buf(10);
            xProxy_oracle_DataAnalyse(data_stream,(enum TNS_COLUMN_TYPE)oracle->columns_select_type[column_index],column_string);

            INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x10_DATA() column_index %d,src_len %d,column_data_string %s",
                        column_index,data_stream_len,(column_string->buf));
            
            destroy_sniffer_buf(data_stream);
            data_stream = NULL;

            destroy_sniffer_buf(column_string);
            column_string = NULL;

            column_index++;
        }
    }
    
    return offset;
}

void xProxy_oracle_TNS_Data_0x11(struct sniffer_session * session,uint32_t offset)
{
    /*
        0x11包 包含0x03 0x5e
        Client -> Server:
            #Data flag [0x00 0x00]
            #Data id   [0x11]
            #Call id
            #Data ......
    */
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->from_upstream?oracle->downstream_buf:oracle->upstream_buf;

    while(offset < (len_sniffer_buf(buf) - 1))
    {
       if(0x03 == (index_sniffer_buf(buf,offset)&0xff) && 
            (0x5e == (index_sniffer_buf(buf,offset + 1)&0xff) || 0x05 == (index_sniffer_buf(buf,offset + 1)&0xff) || 
            0x3b == (index_sniffer_buf(buf,offset + 1)&0xff) || 0x47 == (index_sniffer_buf(buf,offset + 1)&0xff) ||
            0x60 == (index_sniffer_buf(buf,offset + 1)&0xff)))
        {
            offset++;
            INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x11() change to %s","xProxy_oracle_TNS_Data_0x03");

            if(0 == oracle->from_upstream)
            {
                oracle->dataID_query = 0x03;
            }

            xProxy_oracle_TNS_Data_0x03(session,offset);
            break;
        }
        else
        {
            offset++;
        }
    }
}

//Get the session key.
void xProxy_oracle_TNS_Data_0x03_0x76(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * user_name = init_sniffer_buf(128);
    struct sniffer_buf * buf = oracle->upstream_buf;

    //字符串逐个查找. AUTH_TERMINAL & AUTH_PROGRAM_NM & AUTH_MACHINE & AUTH_SID
    while(offset + 4 < len_sniffer_buf(buf))
    {
        //AUTH_TERMINAL
        if('A' == index_sniffer_buf(buf,offset) && 
            'U' == index_sniffer_buf(buf,offset + 1) && 
            'T' == index_sniffer_buf(buf,offset + 2) && 
            'H' == index_sniffer_buf(buf,offset + 3) && 
            '_' == index_sniffer_buf(buf,offset + 4))
        {
            if(len_sniffer_buf(user_name) > 1)
            {
                break;
            }
        }

        if(isalnum(index_sniffer_buf(buf,offset)) || '_' == index_sniffer_buf(buf,offset) || 
            '#' == index_sniffer_buf(buf,offset) || '$' == index_sniffer_buf(buf,offset))
        {
            pushback_sniffer_buf(user_name,index_sniffer_buf(buf,offset));
        }

        offset = offset + 1;
    }

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x76() user_name %s",(user_name->buf));

    session->login_user = init_sniffer_buf(user_name->buf,user_name->used);

    destroy_sniffer_buf(user_name);
    user_name = NULL;
}

//Generic authentication call.
void xProxy_oracle_TNS_Data_0x03_0x73(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * user_name = init_sniffer_buf(128);
    struct sniffer_buf * buf = oracle->upstream_buf;

    //字符串逐个查找. AUTH_SESSKEY & AUTH_PASSWORD
    while(offset + 4 < len_sniffer_buf(buf))
    {
        //AUTH_SESSKEY
        if('A' == index_sniffer_buf(buf,offset) && 
            'U' == index_sniffer_buf(buf,offset + 1) && 
            'T' == index_sniffer_buf(buf,offset + 2) && 
            'H' == index_sniffer_buf(buf,offset + 3) && 
            '_' == index_sniffer_buf(buf,offset + 4))
        {
            if(len_sniffer_buf(user_name) > 1)
            {
                break;
            }
        }

        if(isalnum(index_sniffer_buf(buf,offset)) || '_' == index_sniffer_buf(buf,offset) || 
            '#' == index_sniffer_buf(buf,offset) || '$' == index_sniffer_buf(buf,offset))
        {
            pushback_sniffer_buf(user_name,index_sniffer_buf(buf,offset));
        }

        offset = offset + 1;
    }

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x73() user_name %s",(user_name->buf));

    destroy_sniffer_buf(user_name);
    user_name = NULL;
}

//SQL
void xProxy_oracle_TNS_Data_0x03_0x5e(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * buf = oracle->from_upstream?oracle->downstream_buf:oracle->upstream_buf;
    uint32_t sql_len = 0;
    struct sniffer_buf *sql = NULL;

    //偏移一个固定的位置.
    offset = offset + 6;

    enum TNS_0x03_0x5e_Len_Type tns_len_type = (enum TNS_0x03_0x5e_Len_Type)(index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x5e() offset %d,tns_len_type %d",(offset - 1),tns_len_type);
    if(TNS_0x03_0x5e_Len_0 == tns_len_type)
    {
        xProxy_oracle_TNS_Data_0x03_0x5e_Len_0(session,offset);
        return;
    }
    else if(TNS_0x03_0x5e_Len_1 == tns_len_type)
    {
        sql_len = (index_sniffer_buf(buf,offset)&0xff);
        offset = offset + 1;
    }
    else if(TNS_0x03_0x5e_Len_2 == tns_len_type)
    {
        sql_len = ((index_sniffer_buf(buf,offset)&0xff) << 8) + (index_sniffer_buf(buf,offset)&0xff);
        offset = offset + 2;
    }

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x5e() tns_len_type %d,sql_len %d",tns_len_type,sql_len);

    while(offset < (len_sniffer_buf(buf) - 4))
    {
        //select/update/insert/delete/alter/grant/begin/declare ......
        if(_IsPrintEnglish(index_sniffer_buf(buf,offset)) && _IsPrintEnglish(index_sniffer_buf(buf,offset + 1)) &&
            _IsPrintEnglish(index_sniffer_buf(buf,offset + 2)) && _IsPrintEnglish(index_sniffer_buf(buf,offset + 3)))
        {
            //判断是不是关键字.
            char temp[10] = {0};
            memcpy(temp,(buf->buf + offset),6);
            if(_IsOracleBeginStr(temp))
            {
                break;
            }
        }

        offset++;
    }

    sql = init_sniffer_buf(sql_len + 1);
    cat_sniffer_buf(sql,(buf->buf + offset),sql_len);

    session->current_sql = init_sniffer_buf(sql->buf,sql_len);

    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x5e() sql %s,sql_len %d",(sql->buf),sql_len);
    destroy_sniffer_buf(sql);
    sql = NULL;
}

void xProxy_oracle_TNS_Data_0x03_0x05(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data_0x03_0x05() %s","Fecth a row");
}

void xProxy_oracle_TNS_Data_0x03_0x0e(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Data_0x03_0x0e");
}

void xProxy_oracle_TNS_Data_0x03_0x3b(struct sniffer_session * session,uint32_t offset)
{
    DEBUG_LOG("sniffer_oracle.cpp:%s()","xProxy_oracle_TNS_Data_0x03_0x3b");
}

void xProxy_oracle_TNS_Data_0x03_0x5e_Len_0(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    struct sniffer_buf * sql = init_sniffer_buf(64);
    struct sniffer_buf * buf = oracle->upstream_buf;
    uint32_t i = 0;

    /*
        开始语句的前一个字节的长度.
    */
    uint16_t len_pos_pre = 0x00;

    while((offset + 4) < len_sniffer_buf(buf))
    {
        //select/update/insert/delete/alter/grant/begin/declare ......
        if(_IsPrintEnglish(index_sniffer_buf(buf,offset)) && _IsPrintEnglish(index_sniffer_buf(buf,offset+1)) &&
            _IsPrintEnglish(index_sniffer_buf(buf,offset+2)) && _IsPrintEnglish(index_sniffer_buf(buf,offset+3)))
        {
            //判断是不是关键字.
            char temp[10] = {0};
            memcpy(temp,buf->buf + offset,6);
            if(_IsOracleBeginStr(temp))
            {
                break;
            }
        }

        offset++;
    }

    len_pos_pre = index_sniffer_buf(buf,offset - 1)&0xff;
    INFO_LOG("sniffer_oracle.cpp::xProxy_oracle_TNS_Data_0x03_0x5e_Len_0() offset %d,len_pos_pre 0x%02x 0x%02x",
        offset,index_sniffer_buf(buf,offset - 2),len_pos_pre);

    //<<<Magic Byte>> 0x40.
    if(0x40 > len_pos_pre)
    {
        for(i = offset; (i - offset) < len_pos_pre; i++)
        {
            pushback_sniffer_buf(sql,index_sniffer_buf(buf,i));
        }
    }
    else if(0x40 == len_pos_pre)
    {
        while(index_sniffer_buf(buf,offset) != 0x00)
        {
            pushback_sniffer_buf(sql,index_sniffer_buf(buf,offset));
            offset++;
        }
    }
    else if(0x40 < len_pos_pre)
    {
        for(i = offset; (i - offset) < len_pos_pre; i++)
        {
            pushback_sniffer_buf(sql,index_sniffer_buf(buf,i));
        }
    }

    INFO_LOG("sniffer_oracle.cpp::xProxy_oracle_TNS_Data_0x03_0x5e_Len_0() sql %s",sql->buf);

    session->current_sql = init_sniffer_buf(sql->buf,sql->used);
    destroy_sniffer_buf(sql);
    sql = NULL;
}

void xProxy_oracle_TNS_Data_0x03_0x4e(struct sniffer_session * session,uint32_t offset)
{

}

void xProxy_oracle_TNS_Data(struct sniffer_session * session,uint32_t offset)
{
    struct st_oracle * oracle = (struct st_oracle *)session->db_features;
    //Data flag 0x00 0x00 [2]
    uint16_t quit_flag = 0;
    struct sniffer_buf *buf = NULL;
    uint16_t dataID = 0;

    if(oracle->from_upstream)
    {
        buf = oracle->downstream_buf;
    }
    else
    {
        buf = oracle->upstream_buf;
    }
    
    memcpy(&quit_flag,buf->buf + offset,2);
    offset = offset + 2;

    if(!oracle->from_upstream && quit_flag > 0)
    {
        INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data() client quit %s","");
        return;
    }

    dataID = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    INFO_LOG("sniffer_oracle.cpp:xProxy_oracle_TNS_Data() dataID 0x%02x",dataID);
    if(0 == oracle->from_upstream)
    {
        oracle->dataID_query = dataID;
    }

    switch (dataID)
    {
        //Set Protocol.
        case 0x01:
        {
            xProxy_oracle_TNS_Data_0x01(session,offset);
            break;
        }

        //Set Datatypes.
        case 0x02:
        {
            xProxy_oracle_TNS_Data_0x02(session,offset);
            break;
        }

        //SQL语句
        case 0x03:
        {
            xProxy_oracle_TNS_Data_0x03(session,offset);
            break;
        }

        //Return Status.
        case 0x04:
        {
            //用户名密码\SQL语句错误时，返回错误信息.
            xProxy_oracle_TNS_Data_0x04(session,offset);
            break;
        }
        
        //Row Transfer Header. 
        case 0x06:
        {
            //Data_0x03_0x05的返回值.
            xProxy_oracle_TNS_Data_0x06(session,offset);
            break;
        }

        //Return OPI Parameter.
        case 0x08:
        {
            xProxy_oracle_TNS_Data_0x08(session,offset);
            break;
        }

        //Function Complete
        case 0x09:
        {
            xProxy_oracle_TNS_Data_0x09(session,offset);
            break;
        }

        //Describe Information.
        case 0x10:
        {
            //返回结果集.
            xProxy_oracle_TNS_Data_0x10(session,offset);
            break;
        }

        //可能包含0x03 0x5e
        case 0x11:
        {
            xProxy_oracle_TNS_Data_0x11(session,offset);
            break;
        }

        //Secure Network Service
        case 0xde:
        {
            break;
        }

        default:
        {
            break;
        }
    }
}

void xProxy_oracle_DataAnalyse(struct sniffer_buf* data_src,enum TNS_COLUMN_TYPE data_type,struct sniffer_buf *data_string)
{
    uint32_t offset = 0;

    if(TNS_COLUMN_TYPE_UNKNOWN == data_type)
    {
        ERROR_LOG("sniffer_oracle.cpp:xProxy_oracle_DataAnalyse() data_type %d NOT_DEAL",data_type);
        return;
    }

    //整数需要的变量.
    uint16_t token = 0;
	uint32_t intLen = 0;
	uint32_t intResult = 0;
	uint32_t pow = intLen;
    uint32_t int_index = 0;
    char number_char[20] = {0};

    //Data/Timestamp需要的变量
    char time_char[64] = {0};
    char char_nanosecond[16] = {0};
    uint32_t nanosecond = 0;

    /*
        数据格式:数据长度+实际数据.

        返回该部分的所有长度。
    */

    switch (data_type)
    {
        case TNS_COLUMN_TYPE_VARCHAR2:
        {
            cat_sniffer_buf(data_string,data_src->buf,len_sniffer_buf(data_src));
            break;
        }

        case TNS_COLUMN_TYPE_CHAR:
        {
            while(offset < len_sniffer_buf(data_src))
            {
                if(0x20 == index_sniffer_buf(data_src,offset))
                {
                    break;
                }
                
                pushback_sniffer_buf(data_string,index_sniffer_buf(data_src,offset));
                offset = offset + 1;
            }

            break;
        }
        
        case TNS_COLUMN_TYPE_ROWNUM:
        case TNS_COLUMN_TYPE_NUMBER:
        {   
            //此处只计算整数部分.
            token = (index_sniffer_buf(data_src,offset)&0xff);
            if(token < 0x3f && 
                0x66 == (index_sniffer_buf(data_src,len_sniffer_buf(data_src) - 1)&0xff))
            {
                /*
                    >数据的第一位标志整数部分长度  *** 最后一位 Magic 0x66.
                    >整数部分长度+小数部分长度=数据总长度-2
                    >整数部分从后向前每两位（代表0到100）用一个字节（十六进制）表示，且为101-十六进制值
                    >小数部分从后向前每两位（代表0到100）用一个字节（十六进制）表示，且为101-十六进制值
                    >如果没有小数部分，Intlength+2〉length（为数字长度），则后面有（Intlength+2-length）位（只传输位）值为0的数据没有传输
                */
                intLen = 0x3f - token;
                pow = intLen;
                
                if (intLen > 0)
                {
				    for (int_index = 1; int_index < (len_sniffer_buf(data_src) - 1); int_index++)
                    {
					    intResult += _ZPow(pow - 1) * (101- (index_sniffer_buf(data_src,int_index)&0xff));
					    pow--;
				    }
			    }

                sprintf(number_char,"-%u",intResult);
            }
            else
            {
                /*
                    >数据的第一位标志整数部分长度
                    >整数部分长度+小数部分长度=数据总长度-1
                    >整数部分从后向前每两位（代表0到100）用一个字节（十六进制）表示，且为十六进制值-1
                    >小数部分从后向前每两位（代表0到100）用一个字节（十六进制）表示，且为十六进制值-1
                    >如果没有小数部分，Intlength+1〉length（为数字长度），则后面有（Intlength+1-length）位（只传输位）值为0的数据没有传输
                */
                intLen = token - 0xc0;
                pow = intLen;

                if (intLen > 0)
                {
				    for (int_index = 1; int_index < len_sniffer_buf(data_src) && (int_index < (intLen + 1)); int_index++)
                    {
					    intResult += _ZPow(pow - 1) * (index_sniffer_buf(data_src,int_index) - 1);
					    pow--;
				    }
			    }

                sprintf(number_char,"%u",intResult);
            }

            cat_sniffer_buf(data_string,number_char,strlen(number_char));

            break;
        }

        case TNS_COLUMN_TYPE_DATE:
        {
            if(len_sniffer_buf(data_src) < 7)
            {
                strcpy(time_char,"(null)");
            }
            else
            {
                sprintf(time_char,"%02d%02d-%02d-%02d %02d:%02d:%02d",
                    ((index_sniffer_buf(data_src,0)&0xff) - 0x64),((index_sniffer_buf(data_src,1)&0xff) - 0x64),
                    (index_sniffer_buf(data_src,2)&0xff),
                    (index_sniffer_buf(data_src,3)&0xff),
                    ((index_sniffer_buf(data_src,4)&0xff) - 0x01),
                    ((index_sniffer_buf(data_src,5)&0xff) - 0x01),
                    ((index_sniffer_buf(data_src,6)&0xff) - 0x01));
            }

            cat_sniffer_buf(data_string,time_char,strlen(time_char));
            break;
        }

        case TNS_COLUMN_TYPE_TIMESTAMP:
        {
            if(len_sniffer_buf(data_src) < 7)
            {
                strcpy(time_char,"(null)");
            }
            else
            {
                sprintf(time_char,"%02d%02d-%02d-%02d %02d:%02d:%02d",
                    ((index_sniffer_buf(data_src,0)&0xff) - 0x64),((index_sniffer_buf(data_src,1)&0xff) - 0x64),
                    (index_sniffer_buf(data_src,2)&0xff),
                    (index_sniffer_buf(data_src,3)&0xff),
                    ((index_sniffer_buf(data_src,4)&0xff) - 0x01),
                    ((index_sniffer_buf(data_src,5)&0xff) - 0x01),
                    ((index_sniffer_buf(data_src,6)&0xff) - 0x01));
                cat_sniffer_buf(data_string,time_char,strlen(time_char));

                if(0x0b == len_sniffer_buf(data_src))
                {
                    nanosecond = index_sniffer_buf(data_src,7)*256*256*256;
                    nanosecond += index_sniffer_buf(data_src,8)*256*256;
                    nanosecond += index_sniffer_buf(data_src,9)*256;
                    nanosecond += index_sniffer_buf(data_src,10);

                    sprintf(char_nanosecond,".%06d",nanosecond);

                    cat_sniffer_buf(data_string,char_nanosecond,strlen(char_nanosecond));
                }
            }

            break;
        }

        /* ROWID 暂未解析.
        case TNS_COLUMN_TYPE_ROWID:
        {
            xProxy_db_oracle_ROWID(data_src,data_string,6);
            break;
        }
        */

        default:
        {
            cat_sniffer_buf(data_string,"Not_Parase",10);
            break;
        }
    }
}
