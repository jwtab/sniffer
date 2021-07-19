
#include <sniffer_oracle.h>
#include <sniffer_log.h>

const char * G_TNS_TYPE_NAME[TNS_TYPE_MAX] = {
    "ZERO",
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

static bool _IsPrintEnglish(char c)
{
    //大写字母 A～Z; 小写字母 a～z.
    if((0x41 <= c && c <= 0x5a) || (0x61 <= c && c <= 0x7a))
    {
        return true;
    }

    return false;
}

static bool _IsOracleBeginStr(string str)
{
    transform(str.begin(), str.end(), str.begin(), ::tolower);

    if(0 == memcmp(str.data(),"select",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"update",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"insert",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"delete",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"create",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"drop",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"alter",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"grant",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"begin",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"declare",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"revoke",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"begin",5))
    {
        return true;
    }
    else if(0 == memcmp(str.data(),"call",4))
    {
        return true;
    }

    return false;
}

int dispatch_data_oracle(sniffer_session *session,const char * data,uint32_t data_len)
{
    if(data_len <= 0)
    {
        ERROR_LOG("sniffer_oracle.cpp:dispatch_data_oracle() data_len %d",data_len);
        return 0;
    }

    DEBUG_LOG("sniffer_oracle.cpp:dispatch_data_oracle() from_upstream %d",session->from_upstream);

    if(session->from_upstream)
    {
        //下行流量.
        return dispatch_data_oracle_downstream(session,data,data_len);
    }
    else
    {
        //上行流量.
        return dispatch_data_oracle_upstream(session,data,data_len);
    }

    return 0;
}

int dispatch_data_oracle_upstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    if(data_len < ORACLE_HEAD_LEN)
    {
        ERROR_LOG("sniffer_oracle.cpp:dispatch_data_oracle_upstream() data_len %d",data_len);
        return 1;
    }

    //TNS_HEADER 要提前转化位主机字节序.
    TNS_HEADER _tns_header;
    uint32_t offset = 0;

    memcpy(&_tns_header,data,ORACLE_HEAD_LEN);

    //网络字节序转为主机字节序.
    _tns_header.packet_len = ntohs(_tns_header.packet_len);
   
    offset = ORACLE_HEAD_LEN;

    DEBUG_LOG("sniffer_oracle.cpp:dispatch_data_oracle_upstream() packet_len %d,packet_type %s",
        _tns_header.packet_len,G_TNS_TYPE_NAME[_tns_header.packet_type]);

    switch (_tns_header.packet_type)
    {
        case TNS_TYPE_CONNECT:
        {
            session->op_start = sniffer_log_time_ms();
            Dump_TNS_Connect(session,data + offset,data_len - offset);
            break;
        }

        case TNS_TYPE_DATA:
        {
            session->op_start = sniffer_log_time_ms();
            Dump_TNS_Data(session,data + offset,data_len - offset);
            break;
        }

        default:
            break;
    }

    return 0;
}

void Dump_TNS_Connect(sniffer_session *session,const char * data,uint32_t len)
{
    /*
        格式
        Service Name:
            (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=172.16.0.64)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=D:\Program Files\ABC.exe)(HOST=aaa)(USER=xxx))))
        SID:
            (DESCRIPTION=(CONNECT_DATA=(SID=orcl)(CID=(PROGRAM=SQL Developer)(HOST=__jdbc__)(USER=xxx)))(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.56.201)(PORT=1521)))
    */

    LPTNS_CONNECT lpTNSConnect = (LPTNS_CONNECT)data;
    string connect_data = "";
    string tmp = "";
    string _current_sid = "";

    size_t start_pos = string::npos;
    size_t stop_pos = string::npos;

    uint16_t connect_data_len = 0;
    uint16_t connect_data_pos = 0;

    //pos是相对于tns_header的偏移位置.
    connect_data_pos = ntohs(lpTNSConnect->connect_data_pos) - ORACLE_HEAD_LEN;
    connect_data_len = ntohs(lpTNSConnect->connect_data_len);

    for(uint16_t i = 0; i < connect_data_len; i++)
    {
        connect_data.push_back(data[connect_data_pos + i]);
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
    else
    {
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
    }

    if(_current_sid.length() > 0)
    {
        session->login_with_schema = init_sniffer_buf(_current_sid.c_str(),_current_sid.length());
    }

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Connect() connect_data %s",connect_data.c_str());
}

void Dump_TNS_Data(sniffer_session *session,const char * data,uint32_t len)
{
    uint32_t offset = 0;
    uint16_t data_flag = 0;

    //Data flag 0x00 0x00
    offset = 2;
    memcpy(&data_flag,data,offset);
    
    //退出标记，不再解析.
    if(data_flag > 0)
    {
        INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data() Data flag %s","<<QUIT>>");
        return;
    }

    uint16_t dataID = data[offset];
    offset = offset + 1;

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Data() Data id[HEX] 0x%02x",dataID);

    switch (dataID)
    {
        //Set Protocol.
        case 0x01:
            {
                Dump_TNS_Data_0x01(session,data + offset,len - offset);
                break;
            }

        //Set Datatypes.
        case 0x02:
            {
                Dump_TNS_Data_0x02(session,data + offset,len - offset);
                break;
            }

        //SQL语句
        case 0x03:
            {
                Dump_TNS_Data_0x03(session,data + offset,len - offset);
                break;
            }

        //可能包含0x03 0x5e
        case 0x11:
            {
                Dump_TNS_Data_0x11(session,data + offset,len - offset);
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

void Dump_TNS_Data_0x01(sniffer_session *session,const char * data,uint32_t len)
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
}

void Dump_TNS_Data_0x02(sniffer_session *session,const char * data,uint32_t len)
{

}

void Dump_TNS_Data_0x03(sniffer_session *session,const char * data,uint32_t len)
{
    /*
        0x03包
        Client -> Server:
            #Data flag [0x00 0x00]
            #Data id   [0x03]
            #Call id
            #Data ......
    */
    uint32_t pos = 0;
    uint16_t callID = data[pos];
    pos = pos + 1;

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03() Call id[hex] 0x%02x",callID);

    switch (callID)
    {
        //Get the session key.
        case 0x76:
        {
            Dump_TNS_Data_0x03_0x76(session,data + pos,len - pos);
            break;
        }

        //Generic authentication call.
        case 0x73:
        {
            Dump_TNS_Data_0x03_0x73(session,data + pos,len - pos);
            break;
        }

        //SQL || SQL Prepare.
        case 0x5e:
        {
            Dump_TNS_Data_0x03_0x5e(session,data + pos,len - pos);
            break;
        }

        //SQL Prepare Execute and Fetch.
        case 0x4e:
        {
            Dump_TNS_Data_0x03_0x4e(session,data + pos,len - pos);
            break;
        }

        default:
            break;
    }
}

void Dump_TNS_Data_0x11(sniffer_session *session,const char * data,uint32_t len)
{
    /*
        0x11包 包含0x03
        Client -> Server:
            #Data flag [0x00 0x00]
            #Data id   [0x11]
            #Call id
            #Data ......
    */
    uint32_t pos = 0;
    uint16_t callID = data[pos];

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x11() Call id[hex] 0x%02x",callID);
    for (pos = 0; (pos + 1) < len; pos++)
    {
        if(0x03 == data[pos] && 
            (0x5e == data[pos + 1] || 0x05 == data[pos + 1] || 
             0x3b == data[pos + 1] || 0x47 == data[pos + 1] ||
             0x60 == data[pos + 1]))
        {
            pos++;
            Dump_TNS_Data_0x03(session,data + pos,len - pos);
            break;
        }
    }
}

void Dump_TNS_Data_0x03_0x76(sniffer_session *session,const char * data,uint32_t len)
{
    string _current_user = "";

    //获取用户名.
    uint32_t offset = 0;

    while(offset + 4 < len)
    {
        //AUTH_TERMINAL
        if('A' == data[offset] && 'U' == data[offset + 1] && 'T' == data[offset + 2] && 
            'H' == data[offset + 3] && '_' == data[offset + 4])
        {
            if(_current_user.length() > 1)
            {
                break;
            }
        }

        if(isalnum(data[offset]) || '_' == data[offset] || 
            '#' == data[offset] || '$' == data[offset])
        {
            _current_user.push_back(data[offset]);
        }

        offset = offset + 1;
    }

    if(_current_user.length() > 0)
    {
        session->login_user = init_sniffer_buf(_current_user.c_str(),_current_user.length());

        //上报登录日志.
        session->err_code = 0;
        session->op_end = sniffer_log_time_ms();
        sniffer_session_log(session,true);
    }

    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x76() current_user %s",_current_user.c_str());
}

void Dump_TNS_Data_0x03_0x73(sniffer_session *session,const char * data,uint32_t len)
{
    //再次获取用户名.
    uint32_t offset = 0;
    string temp = "";

    while(offset + 4 < len)
    {
        //AUTH_PASSWORD
        if('A' == data[offset] && 'U' == data[offset + 1] && 'T' == data[offset + 2] && 
            'H' == data[offset + 3] && '_' == data[offset + 4])
        {
            if(temp.length() > 1)
            {
                break;
            }
        }

        if(isalnum(data[offset]) || '_' == data[offset] || 
            '#' == data[offset] || '$' == data[offset])
        {
            temp.push_back(data[offset]);
        }

        offset = offset + 1;
    }

    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x73() current_user %s",temp.c_str());
}

void Dump_TNS_Data_0x03_0x5e(sniffer_session *session,const char * data,uint32_t len)
{
    TNS_0x03_0x5e_Len_Type _tnsLenType = TNS_0x03_0x5e_Len_Type(data[0x06]);
    uint32_t sqlLen = 0;
    string sql = "";

    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e() tnsLenType %d",_tnsLenType);

    if(TNS_0x03_0x5e_Len_1 == _tnsLenType)
    {
        sqlLen = (data[0x07]&0xFF);
    }
    else if(TNS_0x03_0x5e_Len_2 == _tnsLenType)
    {
        sqlLen = ((data[0x07]&0xFF) << 8) + (data[0x08]&0xFF);
    }
    else if(TNS_0x03_0x5e_Len_0 == _tnsLenType)
    {
        Dump_TNS_Data_0x03_0x5e_Len_0(session,data,len);
        return;
    }

    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e() tnsLenType %d,sqlLen %d",_tnsLenType,sqlLen);

    uint32_t pos = 0;
    while(pos < len && ((pos + 4) < len))
    {
        //select/update/insert/delete/alter/grant/begin/declare ......
        if(_IsPrintEnglish(data[pos]) && _IsPrintEnglish(data[pos + 1]) &&
            _IsPrintEnglish(data[pos + 2]) && _IsPrintEnglish(data[pos + 3]))
        {
            //判断是不是关键字.
            char temp[10] = {0};
            memcpy(temp,data + pos,6);
            if(_IsOracleBeginStr(temp))
            {
                break;
            }
        }

        pos++;
    }

    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e() sql_pre_Value 0x%02x",data[pos - 1]);

    for(uint32_t i = pos; (i - pos) < sqlLen; i++)
    {
        sql.push_back(data[i]);
    }

    if(sql.length() > 0)
    {
        session->current_sql = init_sniffer_buf(sql.c_str(),sql.length());

        //上报sql日志.
        session->err_code = 0;
        session->op_end = sniffer_log_time_ms();
        sniffer_sql_log(session);
    }

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e() sql %s,len %d",sql.c_str(),sql.length());
}

void Dump_TNS_Data_0x03_0x4e(sniffer_session *session,const char * data,uint32_t len)
{

}

void Dump_TNS_Data_0x03_0x5e_Len_0(sniffer_session *session,const char * data,uint32_t len)
{
    uint32_t pos = 0;
    string sql = "";

    /*
        开始语句的前一个字节的长度.
    */
    uint16_t len_pos_pre = 0x00;

    while(pos < len && ((pos + 4) < len))
    {
        //select/update/insert/delete/alter/grant/begin/declare ......
        if(_IsPrintEnglish(data[pos]) && _IsPrintEnglish(data[pos + 1]) &&
            _IsPrintEnglish(data[pos + 2]) && _IsPrintEnglish(data[pos + 3]))
        {
            //判断是不是关键字.
            char temp[10] = {0};
            memcpy(temp,data + pos,6);
            if(_IsOracleBeginStr(temp))
            {
                break;
            }
        }

        pos++;
    }

    len_pos_pre = data[pos - 1];
    INFO_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e_Len_0() start_pos %d,len_pos_pre 0x%02x 0x%02x",
        pos,data[pos - 2],len_pos_pre);

    //<<<Magic Byte>> 0x40.
    if(0x40 > len_pos_pre)
    {
        for(uint16_t i = pos; (i - pos) < len_pos_pre; i++)
        {
            sql.push_back(data[i]);
        }
    }
    else if(0x40 == len_pos_pre)
    {
        while(data[pos] != 0x00)
        {
            sql.push_back(data[pos]);
            pos++;
        }
    }
    else if(0x40 < len_pos_pre)
    {
        for(uint16_t i = pos; (i - pos) < len_pos_pre; i++)
        {
            sql.push_back(data[i]);
        }
    }

    if(sql.length() > 0)
    {
        session->current_sql = init_sniffer_buf(sql.c_str(),sql.length());

        //上报sql日志.
        session->err_code = 0;
        session->op_end = sniffer_log_time_ms();
        sniffer_sql_log(session);
    }

    DEBUG_LOG("sniffer_oracle.cpp:Dump_TNS_Data_0x03_0x5e_Len_0() sql %s,len %d",sql.c_str(),sql.length());
}

int dispatch_data_oracle_downstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    return 0;
}
