
#include <sniffer_inc.h>

#include <sniffer_cfg.h>
#include <sniffer_dev.h>
#include <sniffer_log.h>
#include <sniffer_sess.h>

static volatile int is_shutdown;

void sig_exit_handler(int sig)
{
    is_shutdown = 1;
}

int sniffer_is_shutdown()
{
    return is_shutdown == 1;
}

static void dispatch_db_data(struct sniffer_session * sess,const char * data,int data_len)
{
    if(sess->data_fun)
    {
        sess->data_fun(sess,data,data_len);
    }
}

int dispatch_db(tcp_stream stream,const char * data,int data_len)
{
    string hash_key = "";

    if(stream.state == NIDS_JUST_EST)
    {
        DEBUG_LOG("main.cpp:dispatch_db() state %s [%s:%d -> %s:%d]","NIDS_JUST_EST",
                stream.from_ip.c_str(),stream.from_port,
                stream.to_ip.c_str(),stream.to_port);
        
        sniffer_session_key(stream,hash_key);
        sniffer_session_add(hash_key.c_str(),stream);

        INFO_LOG("main.cpp:dispatch_db() state %s session_key %s","NIDS_JUST_EST",hash_key.c_str());
    }
    else if(stream.state == NIDS_CLOSE)
    {
        DEBUG_LOG("main.cpp:dispatch_db() state %s [%s:%d -> %s:%d]","NIDS_CLOSE",
                stream.from_ip.c_str(),stream.from_port,
                stream.to_ip.c_str(),stream.to_port);
        
        sniffer_session_key(stream,hash_key);
        sniffer_session_delete(hash_key.c_str());

        INFO_LOG("main.cpp:dispatch_db() state %s session_key %s","NIDS_CLOSE",hash_key.c_str());
    }
    else if(stream.state == NIDS_DATA)
    {
        DEBUG_LOG("main.cpp:dispatch_db() state %s [%s:%d -> %s:%d]","NIDS_DATA",
                stream.from_ip.c_str(),stream.from_port,
                stream.to_ip.c_str(),stream.to_port);
        
        sniffer_session_key(stream,hash_key);
        INFO_LOG("main.cpp:dispatch_db() state %s session_key %s","NIDS_DATA",hash_key.c_str());

        struct sniffer_session *sess = sniffer_session_get(hash_key.c_str());
        if(sess)
        {
            sess->from_upstream = !strcasecmp(stream.from_ip.c_str(),sniffer_cfg_capip().c_str());
            dispatch_db_data(sess,data,data_len);
        }
        else
        {
            WARN_LOG("main.cpp:dispatch_db() state %s session_key %s NOT_FOUND try_deal.","NIDS_DATA",hash_key.c_str());

            sniffer_session_add(hash_key.c_str(),stream);
            sess = sniffer_session_get(hash_key.c_str());
            sess->from_upstream = !strcasecmp(stream.from_ip.c_str(),sniffer_cfg_capip().c_str());

            //不完整的开始会话.
            sess->op_start = sess->op_end = sniffer_log_time_ms();
            sniffer_session_log(sess,true);

            dispatch_db_data(sess,data,data_len);
        }
    }

    return 0;
}

int
main(int argc,char **argv)
{
    int ret = 0;
    if(-1 == sniffer_cfg_init(argc,argv))
    {
        exit(1);
    }

    sniffer_config * config = sniffer_cfg_get();
    sniffer_cfg_print();

    if(sniffer_cfg_daemon())
    {
        daemon(1, 0);
    }

    signal(SIGINT, sig_exit_handler);
    signal(SIGTERM, sig_exit_handler);

    is_shutdown = 0;
    
    if(0 != sniffer_kafka_init())
    {
        FATAL_LOG("mai.cpp:sniffer_kafka_init() %s","error");
        return 1;
    }

    ret = capdev_filter(config->cap_net.c_str(),config->cap_ip.c_str(),config->cap_port);
    if(0 == ret)
    {
        while(!sniffer_is_shutdown())
        {
            capdev_dispatch(dispatch_db);
        }

        capdev_uinit();
    }

    sniffer_kafka_uninit();

    WARN_LOG("\n%s","sniffer waill exit");

    return 0;
}
