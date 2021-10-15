
#include <sniffer_tds.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

int dispatch_data_tds_parseHead(struct st_tds *tds,struct sniffer_buf *buf)
{
    memset(&tds->header,0,TDS_HEAD_LEN);
    memcpy(&tds->header,buf->buf,TDS_HEAD_LEN);

    tds->header.packet_len = ntohs(tds->header.packet_len);

    return TDS_HEAD_LEN;
}

int dispatch_data_tds(sniffer_session *session,const char * data,uint32_t data_len)
{
    if(data_len <= 0)
    {
        ERROR_LOG("sniffer_tds.cpp:dispatch_data_tds() data_len %d",data_len);
        return 0;
    }

    DEBUG_LOG("sniffer_tds.cpp:dispatch_data_tds() from_upstream %d",session->from_upstream);

    if(session->from_upstream)
    {
        //下行流量.
        return dispatch_data_tds_downstream(session,data,data_len);
    }
    else
    {
        //上行流量.
        return dispatch_data_tds_upstream(session,data,data_len);
    }

    return 0;
}

int dispatch_data_tds_upstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->upstream_buf;
    uint32_t offset = 0;

    cat_sniffer_buf(buf,(const char*)data,data_len);

    if(len_sniffer_buf(buf) < TDS_HEAD_LEN)
    {
        WARN_LOG("sniffer_tds.cpp:dispatch_data_tds_upstream() buf_len %d NOT_MEET_TDS_HEAD",len_sniffer_buf(buf));
        return data_len;
    }

    offset = dispatch_data_tds_parseHead(proxy_tds,buf);

    if(proxy_tds->header.packet_len > len_sniffer_buf(buf))
    {
        WARN_LOG("sniffer_tds.cpp:dispatch_data_tds_upstream() buf_len %d NOT_MEET_TDS_PACKET",len_sniffer_buf(buf));
        return data_len;
    }

    switch (proxy_tds->header.tds_type)
    {
        case TDS_TYPE_SQLBATCH:
        {
            dispatch_TDS_SQLBATCH(session,offset);
            break;
        }

        case TDS_TYPE_RPC:
        {
            dispatch_TDS_RPC(session,offset);
            break;
        }

        case TDS_TYPE_PRETDS7:
        {
            break;
        }

        case TDS_TYPE_LOGIN7:
        {
            break;
        }

        case TDS_TYPE_PRELOGIN:
        {
            dispatch_TDS_PRELOGIN(session,offset);
            break;
        }

        case TDS_TYPE_BULK:
        {
            break;
        }

        case TDS_TYPE_TRANSACTION:
        {
            dispatch_TDS_TRANSACTION(session,offset);
            break;
        }

        case TDS_TYPE_SSPI:
        {
            break;
        }
    
        default:
        {
            break;
        }
    }

    //重置buf.
    reset_sniffer_buf(proxy_tds->upstream_buf);

    return 0;
}

int dispatch_data_tds_downstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;
    uint32_t offset = 0;

    cat_sniffer_buf(buf,(const char*)data,data_len);

    if(len_sniffer_buf(buf) < TDS_HEAD_LEN)
    {
        WARN_LOG("sniffer_tds.cpp:dispatch_data_tds_downstream() buf_len %d NOT_MEET_TDS_HEAD",len_sniffer_buf(buf));
        return data_len;
    }

    offset = dispatch_data_tds_parseHead(proxy_tds,buf);

    if(proxy_tds->header.packet_len > len_sniffer_buf(buf))
    {
        WARN_LOG("sniffer_tds.cpp:dispatch_data_tds_downstream() buf_len %d NOT_MEET_TDS_PACKET",len_sniffer_buf(buf));
        return data_len;
    }

    switch (proxy_tds->header.tds_type)
    {
        case TDS_TYPE_TABULARRESULT:
        {
            dispatch_TDS_TABULARRESULT(session,offset);
            break;
        }

        case TDS_TYPE_PRETDS7:
        {
            break;
        }

        case TDS_TYPE_LOGIN7:
        {
            break;
        }

        case TDS_TYPE_PRELOGIN:
        {
            dispatch_TDS_PRELOGIN(session,offset);
            break;
        }
    
        default:
        {
            break;
        }
    }

    //重置buf.
    reset_sniffer_buf(proxy_tds->downstream_buf);

    return 0;
}

void dispatch_TDS_SQLBATCH(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->upstream_buf;
    
    struct sniffer_buf *sql = init_sniffer_buf(1024);

    uint32_t header_total_len = 0;
    uint32_t header_len = 0;
    uint32_t header_type = 0;

    //4字节.
    header_total_len = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    //4字节.
    header_len = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    //2字节.
    header_type = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_type += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    if(2 == header_type)
    {
        //8字节
        offset = offset + 8;

        //4字节
        offset = offset + 4;
    }

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_SQLBATCH() stream_total_len %d,header_len %d,header_type %d",header_total_len,header_len,header_type);

    while(offset < len_sniffer_buf(buf))
    {
        if(0x00 != index_sniffer_buf(buf,offset))
        {
            pushback_sniffer_buf(sql,index_sniffer_buf(buf,offset));
        }

        offset++;
    }

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_SQLBATCH() sql_len %d,sql %s",len_sniffer_buf(sql),buf_sniffer_buf(sql,0));

    destroy_sniffer_buf(sql);
    sql = NULL;
}

void dispatch_TDS_PRELOGIN(struct sniffer_session *session,uint32_t offset)
{
    INFO_LOG("sniffer_tds.cpp:%s()","dispatch_TDS_PRELOGIN");

    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = session->from_upstream?proxy_tds->downstream_buf:proxy_tds->upstream_buf;
    
    if(buf)
    {

    }
}

void dispatch_TDS_TABULARRESULT(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;
    
    uint8_t tds_data_token = 0;
    while(1)
    {
        tds_data_token = index_sniffer_buf(buf,offset)&0xff;
        offset = offset + 1;

        if(0x00 == tds_data_token)
        {
            WARN_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() HAVE_NO_TOKEN %s"," ");
            break;
        }

        bool done = false;

        switch (tds_data_token)
        {
            case TDS_TOKEN_TVPROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_TVPROW");
                break;
            }

            case TDS_TOKEN_OFFSET:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_OFFSET");
                break;
            }

            case TDS_TOKEN_RETURNSTATUS:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_RETURNSTATUS");
                offset = offset + dispatch_TDS_TOKEN_RETURNSTATUS(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_COLMETADATA:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_COLMETADATA");
                offset = offset + dispatch_TDS_TOKEN_COLMETADATA(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_ALTMETADATA:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ALTMETADATA");
                break;
            }
            
            case TDS_TOKEN_TABNAME:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_TABNAME");
                break;
            }

            case TDS_TOKEN_COLINFO:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_COLINFO");
                offset = offset + dispatch_TDS_TOKEN_COLINFO(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_ORDER:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ORDER");
                offset = offset + dispatch_TDS_TOKEN_ORDER(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_ERROR:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ERROR");
                offset = offset + dispatch_TDS_TOKEN_ERROR(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_INFO:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_INFO");
                offset = offset + dispatch_TDS_TOKEN_INFO(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_RETURNVALUE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_RETURNVALUE");
                break;
            }

            case TDS_TOKEN_LOGINACK:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_LOGINACK");
                offset = offset + dispatch_TDS_TOKEN_LOGINACK(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_ROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ROW");
                offset = offset + dispatch_TDS_TOKEN_ROW(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_NBCROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_NBCROW");
                break;
            }

            case TDS_TOKEN_ALTROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ALTROW");
                break;
            }

            case TDS_TOKEN_ENVCHANGE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_ENVCHANGE");
                offset = offset + dispatch_TDS_TOKEN_ENVCHANGE(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_SSPI:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_SSPI");
                break;
            }

            case TDS_TOKEN_DONE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_DONE");
                done = true;
                offset = offset + dispatch_TDS_TOKEN_DONE(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_DONEPROC:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_DONEPROC");
                done = true;
                offset = offset + dispatch_TDS_TOKEN_DONEPROC(buf_sniffer_buf(buf,offset));
                break;
            }

            case TDS_TOKEN_DONEINPROC:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() toekn %s","TDS_TOKEN_DONEINPROC");
                offset = offset + dispatch_TDS_TOKEN_DONEINPROC(buf_sniffer_buf(buf,offset));
                break;
            }

            default:
            {
                break;
            }
        }

        if(done)
        {
            break;
        }
    }
}

void dispatch_TDS_TRANSACTION(struct sniffer_session *session,uint32_t offset)
{
    INFO_LOG("sniffer_tds.cpp:%s()","dispatch_TDS_TRANSACTION");
}

void dispatch_TDS_RPC(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->upstream_buf;
    
    struct sniffer_buf *sql = init_sniffer_buf(128);

    uint32_t header_total_len = 0;
    uint32_t header_len = 0;
    uint32_t header_type = 0;
    uint16_t rpc_name_len = 0;
    uint16_t rpc_name_id = 0;

    //4字节.
    header_total_len = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    header_total_len += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    //4字节.
    header_len = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    header_len += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    //2字节.
    header_type = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    header_type += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    if(2 == header_type)
    {
        //8字节
        offset = offset + 8;

        //4字节
        offset = offset + 4;
    }

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_RPC() stream_total_len %d,header_len %d,header_type %d",header_total_len,header_len,header_type);

    //rpc name len 2字节.
    rpc_name_len = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    rpc_name_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //rpc name id 2字节.
    rpc_name_id = (index_sniffer_buf(buf,offset)&0xff);
    offset = offset + 1;

    rpc_name_id += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_RPC() rpc_name_length %d,rpc_name_id %d",rpc_name_len,rpc_name_id);

    switch (rpc_name_id)
    {
        case 1:
        {
            cat_sniffer_buf(sql,"exec Sp_Cursor");
            break;
        }

        case 2:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorOpen");
            break;
        }

        case 3:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorPrepare");
            break;
        }

        case 4:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorExecute");
            break;
        }

        case 5:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorPrepExec");
            break;
        }

        case 6:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorUnprepare");
            break;
        }

        case 7:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorFetch");
            break;
        }

        case 8:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorOption");
            break;
        }

        case 9:
        {
            cat_sniffer_buf(sql,"exec Sp_CursorClose");
            break;
        }

        case 10:
        {
            cat_sniffer_buf(sql,"exec Sp_ExecuteSql");
            break;
        }

        case 11:
        {
            cat_sniffer_buf(sql,"exec Sp_Prepare");
            break;
        }

        case 12:
        {
            cat_sniffer_buf(sql,"exec Sp_Execute");
            break;
        }

        case 13:
        {
            cat_sniffer_buf(sql,"exec Sp_PrepExec");
            break;
        }

        case 14:
        {
            cat_sniffer_buf(sql,"exec Sp_PrepExecRpc");
            break;
        }

        case 15:
        {
            cat_sniffer_buf(sql,"exec Sp_Unprepare");
            break;
        }

        default:
        {
            cat_sniffer_buf(sql,"Unknown RPC ID");
            break;
        }
    }

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_RPC() rpc_name %s",buf_sniffer_buf(sql,0));

    destroy_sniffer_buf(sql);
    sql = NULL;
}

uint32_t dispatch_TDS_TOKEN_ERROR(const char * data)
{
    uint32_t offset = 0;
    uint32_t token_len = 0;
    uint32_t sql_error_number = 0;
    uint16_t error_msg_len = 0;

    //token len 2字节.
    token_len = data[offset]&0xff;
    offset = offset + 1;

    token_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //SQL Error number 4字节.
    sql_error_number = data[offset]&0xff;
    offset = offset + 1;
    
    sql_error_number += (data[offset]&0xff) << 8;
    offset = offset + 1;

    sql_error_number += (data[offset]&0xff) << 16;
    offset = offset + 1;

    sql_error_number += (data[offset]&0xff) << 24;
    offset = offset + 1;

    //State 1字节
    offset = offset + 1;

    //Class 1字节   
    offset = offset + 1;

    //Error msg len 2字节.
    error_msg_len = data[offset]&0xff;
    offset = offset + 1;

    error_msg_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ERROR() token_length %d,error_code %d,error_msg_length %d",
            token_len,sql_error_number,error_msg_len);

    //该token占用的数据长度.
    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_DONE(const char * data)
{
    uint32_t offset = 0;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = data[offset]&0xff;
    offset = offset + 1;

    status_flag += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = data[offset]&0xff;
    offset = offset + 1;

    operation_cmd += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = data[offset]&0xff;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 8;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 16;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONE() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_DONEPROC(const char * data)
{
    uint32_t offset = 0;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = data[offset]&0xff;
    offset = offset + 1;

    status_flag += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = data[offset]&0xff;
    offset = offset + 1;

    operation_cmd += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = data[offset]&0xff;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 8;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 16;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONEPROC() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_DONEINPROC(const char * data)
{
    uint32_t offset = 0;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = data[offset]&0xff;
    offset = offset + 1;

    status_flag += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = data[offset]&0xff;
    offset = offset + 1;

    operation_cmd += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = data[offset]&0xff;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 8;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 16;
    offset = offset + 1;

    row_count += (data[offset]&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONEINPROC() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_COLMETADATA(const char *data)
{
    uint32_t offset = 0;

    uint16_t columns_select = 0;

    //Coulumns 2字节.
    columns_select = data[offset]&0xff;
    offset = offset + 1;

    columns_select += (data[offset]&0xff) << 8;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_COLMETADATA() columns %d",columns_select);

    //逐一解析column.
    for(int i = 0; i < columns_select; i++)
    {
        
    }

    return 0;
}

uint32_t dispatch_TDS_TOKEN_COLINFO(const char *data)
{
    return 0;
}

uint32_t dispatch_TDS_TOKEN_ORDER(const char *data)
{
    uint32_t offset = 0;
    uint32_t token_len = 0;

    //token len 2字节.
    token_len = data[offset]&0xff;
    offset = offset + 1;

    token_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ORDER() token_len %d",token_len);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_LOGINACK(const char *data)
{
    uint32_t offset = 0;
    uint32_t token_len = 0;

    //token len 2字节.
    token_len = data[offset]&0xff;
    offset = offset + 1;

    token_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_LOGINACK() token_len %d",token_len);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_ROW(const char *data)
{
    return 0;
}

uint32_t dispatch_TDS_TOKEN_INFO(const char *data)
{
    uint32_t offset = 0;
    uint32_t token_len = 0;

    //token len 2字节.
    token_len = data[offset]&0xff;
    offset = offset + 1;

    token_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_INFO() token_len %d",token_len);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_RETURNSTATUS(const char *data)
{
    return 0;
}

uint32_t dispatch_TDS_TOKEN_ENVCHANGE(const char *data)
{
    uint32_t offset = 0;
    uint32_t token_len = 0;
    uint8_t type = 0;

    //token len 2字节.
    token_len = data[offset]&0xff;
    offset = offset + 1;

    token_len += (data[offset]&0xff) << 8;
    offset = offset + 1;

    //type 1字节.
    type = data[offset]&0xff;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ENVCHANGE() token_len %d,type %d",token_len,type);

    return (token_len + 2);
}
