
#include <sniffer_tds.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

uint32_t tds_server_version = 0;

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
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_TVPROW");
                break;
            }

            case TDS_TOKEN_OFFSET:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_OFFSET");
                break;
            }

            case TDS_TOKEN_RETURNSTATUS:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_RETURNSTATUS");
                offset = offset + dispatch_TDS_TOKEN_RETURNSTATUS(session,offset);
                break;
            }

            case TDS_TOKEN_COLMETADATA:
            {
                tds_server_version = proxy_tds->tds_server_version;
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_COLMETADATA");
                offset = offset + dispatch_TDS_TOKEN_COLMETADATA(session,offset);
                break;
            }

            case TDS_TOKEN_ALTMETADATA:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ALTMETADATA");
                break;
            }
            
            case TDS_TOKEN_TABNAME:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_TABNAME");
                break;
            }

            case TDS_TOKEN_COLINFO:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_COLINFO");
                offset = offset + dispatch_TDS_TOKEN_COLINFO(session,offset);
                break;
            }

            case TDS_TOKEN_ORDER:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ORDER");
                offset = offset + dispatch_TDS_TOKEN_ORDER(session,offset);
                break;
            }

            case TDS_TOKEN_ERROR:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ERROR");
                offset = offset + dispatch_TDS_TOKEN_ERROR(session,offset);
                break;
            }

            case TDS_TOKEN_INFO:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_INFO");
                offset = offset + dispatch_TDS_TOKEN_INFO(session,offset);
                break;
            }

            case TDS_TOKEN_RETURNVALUE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_RETURNVALUE");
                break;
            }

            case TDS_TOKEN_LOGINACK:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_LOGINACK");
                offset = offset + dispatch_TDS_TOKEN_LOGINACK(session,offset);

                //记录服务器版本.
                proxy_tds->tds_server_version = tds_server_version;
                break;
            }

            case TDS_TOKEN_ROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ROW");
                offset = offset + dispatch_TDS_TOKEN_ROW(session,offset);
                break;
            }

            case TDS_TOKEN_NBCROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_NBCROW");
                break;
            }

            case TDS_TOKEN_ALTROW:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ALTROW");
                break;
            }

            case TDS_TOKEN_ENVCHANGE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_ENVCHANGE");
                offset = offset + dispatch_TDS_TOKEN_ENVCHANGE(session,offset);
                break;
            }

            case TDS_TOKEN_SSPI:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_SSPI");
                break;
            }

            case TDS_TOKEN_DONE:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_DONE");
                if(TDS_TOKEN_STATUS_MORE != index_sniffer_buf(buf,offset))
                {
                    done = true;
                }

                offset = offset + dispatch_TDS_TOKEN_DONE(session,offset);
                break;
            }

            case TDS_TOKEN_DONEPROC:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_DONEPROC");
                done = true;
                offset = offset + dispatch_TDS_TOKEN_DONEPROC(session,offset);
                break;
            }

            case TDS_TOKEN_DONEINPROC:
            {
                DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TABULARRESULT() token %s","TDS_TOKEN_DONEINPROC");
                offset = offset + dispatch_TDS_TOKEN_DONEINPROC(session,offset);
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

uint32_t dispatch_TDS_TOKEN_ERROR(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t token_len = 0;
    uint32_t sql_error_number = 0;
    uint16_t error_msg_len = 0;

    //token len 2字节.
    token_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    token_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //SQL Error number 4字节.
    sql_error_number = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;
    
    sql_error_number += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    sql_error_number += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    sql_error_number += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    //State 1字节
    offset = offset + 1;

    //Class 1字节   
    offset = offset + 1;

    //Error msg len 2字节.
    error_msg_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    error_msg_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ERROR() token_length %d,error_code %d,error_msg_length %d",
            token_len,sql_error_number,error_msg_len);
    
    //该token占用的实际空间.
    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_DONE(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    status_flag += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    operation_cmd += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONE() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_DONEPROC(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    status_flag += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    operation_cmd += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONEPROC() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_DONEINPROC(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint16_t status_flag = 0;
    uint16_t operation_cmd = 0;
    uint64_t row_count = 0;

    //Status flag 2字节.
    status_flag = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    status_flag += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //operation 2字节.
    operation_cmd = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    operation_cmd += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //Row count 4字节<暂时>
    row_count = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    row_count += (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_DONEINPROC() Status_flag %d,op_cmd %d,row_count %d",
            status_flag,operation_cmd,row_count);
    
    return 12;
}

uint32_t dispatch_TDS_TOKEN_COLMETADATA(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t offset_old = offset;

    uint16_t columns_select = 0;

    uint32_t user_type = 0;
    uint16_t flags = 0;
    uint8_t column_type = 0;
    uint32_t size = 0;
    uint32_t column_name_len = 0;
    struct sniffer_buf * column_name = init_sniffer_buf(64);

    //Coulumns 2字节.
    columns_select = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    columns_select += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_COLMETADATA() columns %d",columns_select);

    proxy_tds->columns_select = columns_select;

    if(NULL != proxy_tds->columns_select_type)
    {
        zfree(proxy_tds->columns_select_type);
    }

    proxy_tds->columns_select_type = (uint16_t*)zmalloc(sizeof(uint16_t)*columns_select);

    //逐一解析column.
    for(int i = 0; i < columns_select; i++)
    {
        //user_type 4 OR 2字节.
        user_type = 0;

        if(tds_server_version >= TDS_7_2)
        {
            offset = offset + 4;
        }
        else 
        {
            offset = offset + 2;
        }

        //flags 2字节.
        flags = 0;
        offset = offset + 2;

        //column_type 1
        column_type = index_sniffer_buf(buf,offset)&0xff;
        offset = offset + 1;

        //记录数据类型.
        proxy_tds->columns_select_type[i] = column_type;

        switch (column_type)
        {
            case TDS_DATA_TINYINT:
			case TDS_DATA_SMALLINT:
			case TDS_DATA_INT:
			case TDS_DATA_DATETIME:
			case TDS_DATA_FLOAT:
			case TDS_DATA_REAL:
			case TDS_DATA_SMALLDATETIME:
			case TDS_DATA_BIT:
			case TDS_DATA_BIGINT:
			case TDS_DATA_DATEN:
			case TDS_DATA_MONEY:
			{
                break;
            }

			case TDS_DATA_GUID:
			case TDS_DATA_INTN:
			case TDS_DATA_TIMEN:
			case TDS_DATA_DATETIME2N:
			case TDS_DATA_DATETIMEOFFSETN:
			case TDS_DATA_BITN:
			case TDS_DATA_FLOATN:
			case TDS_DATA_MONEYN:
			case TDS_DATA_DATETIMEN:
			{
                size = index_sniffer_buf(buf,offset)&0xff;
                offset = offset + 1;

				break;
            }

			case TDS_DATA_NVARCHAR:
			{
                offset = offset + 7;
				break;
            }

			case TDS_DATA_SQLVARIANT:
			{
                offset = offset + 4;
				break;
            }

			case TDS_DATA_VARCHARN:
			case TDS_DATA_CHARN:
			case TDS_DATA_NCHAR:
			{
                offset = offset + 7;
				break;
            }

			case TDS_DATA_BINARYN:
			case TDS_DATA_VARBINARYN:
			{
                offset = offset + 2;
				break;
            }

			case TDS_DATA_TEXT:
			case TDS_DATA_NTEXT:
			{
				/*m_br.UB4();
				m_br.UB1();
				m_br.UB4();
				if (m_nPacketType != TDS_HT_BULK){
					m_br.UB1();
				}
				unsigned int size = m_br.UB2();
				if (size > 0){
					m_br.Forward(size*2);
				}
                */
                break;
			}
				
			case TDS_DATA_DECIMALN:
			case TDS_DATA_NUMERICN:
			{
                offset = offset + 2;

				size = index_sniffer_buf(buf,offset)&0xff;
                offset = offset + 1;

				break;
            }

			default:
			{
				break;
            }
		}

        column_name_len = index_sniffer_buf(buf,offset)&0xff;
        offset = offset + 1;

        if(column_name_len > 0)
        {
            //unicode编码长度.
            for(int m = 0; m < column_name_len*2; m++)
            {
                if(0x00 != index_sniffer_buf(buf,offset + m))
                {
                    pushback_sniffer_buf(column_name,index_sniffer_buf(buf,offset + m));
                }
            }

            offset = offset + column_name_len*2;
        }
        else
        {
            cat_sniffer_buf(column_name,"{UnK}");
        }

        INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_COLMETADATA() index %d,type 0x%02x,name %s",
                i+1,column_type,buf_sniffer_buf(column_name,0));

        reset_sniffer_buf(column_name);
    }

    destroy_sniffer_buf(column_name);
    column_name = NULL;

    return (offset - offset_old);
}

uint32_t dispatch_TDS_TOKEN_COLINFO(struct sniffer_session *session,uint32_t offset)
{
    return 0;
}

uint32_t dispatch_TDS_TOKEN_ORDER(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t token_len = 0;

    //token len 2字节.
    token_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    token_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ORDER() token_len %d",token_len);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_LOGINACK(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t token_len = 0;

    //token len 2字节.
    token_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    token_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_LOGINACK() token_len %d",token_len);

    //Interface 1字节.
    offset = offset + 1;

    //tds server version. 确定TDS服务器的版本.
    tds_server_version = (index_sniffer_buf(buf,offset)&0xff) << 24;
    offset = offset + 1;

    tds_server_version += (index_sniffer_buf(buf,offset)&0xff) << 16;
    offset = offset + 1;

    tds_server_version += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    tds_server_version += index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    INFO_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_LOGINACK() TDS VERSION 0x%08x",tds_server_version);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_ROW(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;


    return 0;
}

uint32_t dispatch_TDS_TOKEN_INFO(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t token_len = 0;

    //token len 2字节.
    token_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    token_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_INFO() token_len %d",token_len);

    return (token_len + 2);
}

uint32_t dispatch_TDS_TOKEN_RETURNSTATUS(struct sniffer_session *session,uint32_t offset)
{
    return 0;
}

uint32_t dispatch_TDS_TOKEN_ENVCHANGE(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = proxy_tds->downstream_buf;

    uint32_t token_len = 0;
    uint8_t type = 0;

    //token len 2字节.
    token_len = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    token_len += (index_sniffer_buf(buf,offset)&0xff) << 8;
    offset = offset + 1;

    //type 1字节.
    type = index_sniffer_buf(buf,offset)&0xff;
    offset = offset + 1;

    DEBUG_LOG("sniffer_tds.cpp:dispatch_TDS_TOKEN_ENVCHANGE() token_len %d,type %d",token_len,type);

    return (token_len + 2);
}
