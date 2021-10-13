
#include <sniffer_tds.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

int dispatch_data_tds_parseHead(struct st_tds *tds,struct sniffer_buf *buf)
{
    memcpy(&tds->header,buf->buf,TDS_HEAD_LEN);

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

    return 0;
}

void dispatch_TDS_SQLBATCH(struct sniffer_session *session,uint32_t offset)
{

}

void dispatch_TDS_PRELOGIN(struct sniffer_session *session,uint32_t offset)
{
    struct st_tds * proxy_tds = (struct st_tds*)session->db_features;
    struct sniffer_buf * buf = session->from_upstream?proxy_tds->downstream_buf:proxy_tds->upstream_buf;
    
    if(buf)
    {

    }
}

void dispatch_TDS_TABULARRESULT(struct sniffer_session *session,uint32_t offset)
{

}

void dispatch_TDS_TRANSACTION(struct sniffer_session *session,uint32_t offset)
{

}
