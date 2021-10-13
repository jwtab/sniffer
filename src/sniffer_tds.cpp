
#include <sniffer_tds.h>
#include <sniffer_log.h>
#include <sniffer_cfg.h>

int dispatch_data_tds_parseHead(struct st_tds *tds,struct sniffer_buf *buf)
{
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
        WARN_LOG("sniffer_tds.cpp:dispatch_data_tds_upstream() buf_len %d NOT_MEET_ORACLE_HEAD",len_sniffer_buf(buf));
        return data_len;
    }

    offset = dispatch_data_tds_parseHead(proxy_tds,buf);
    
    return 0;
}

int dispatch_data_tds_downstream(sniffer_session *session,const char * data,uint32_t data_len)
{
    return 0;
}
