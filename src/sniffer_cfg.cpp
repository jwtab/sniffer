
#include <sniffer_cfg.h>

static sniffer_config g_config;

static void sniffer_help(const char * name)
{
    printf("Usage %s [-d] -i eth0 -p 3306 -s 192.168.10.121\n" 
            "         -d daemon mode,Default false\n"
            "         -i interface, Default to eth0\n"
            "         -p port, Default to 3306.\n"
            "         -s serverip, Default to 127.0.0.1.\n"
            "         -k kafka, Default to 127.0.0.1:9092.\n"
            "         -t dbtype, Default to mysql{mysql\\oracle\\postgresql}.\n"
            "         -l logtype, Default to warn{fatal\\error\\warn\\info\\debug}.\n"
            "         -b object_id, Default to 100.\n"
            "         -r max_rowsets, Default to 5.\n"
            ,
            name);
}

static LOG_TYPE cmdline_parse_logtype(const char * opt)
{
    LOG_TYPE type = LOG_TYPE_MAX;

    if(0 == strcasecmp(opt,"error"))
    {
        type = LOG_TYPE_ERROR;
    }
    else if(0 == strcasecmp(opt,"warn"))
    {
        type = LOG_TYPE_WARN;
    }
    else if(0 == strcasecmp(opt,"info"))
    {
        type = LOG_TYPE_INFO;
    }
    else if(0 == strcasecmp(opt,"debug"))
    {
        type = LOG_TYPE_DEBUG;
    }

    if(LOG_TYPE_MAX == type)
    {
        printf("-l logtype, Default to warn{fatal\\error\\warn\\info\\debug}\n");
        exit(1);
    }

    return type;
}

static DB_TYPE cmdline_parse_dbtype(const char * opt)
{
    DB_TYPE type = DB_TYPE_MAX;

    if(0 == strcasecmp(opt,"mysql"))
    {
        type = DB_TYPE_MYSQL;
    }
    else if(0 == strcasecmp(opt,"oracle"))
    {
        type = DB_TYPE_ORACLE;
    }
    else if(0 == strcasecmp(opt,"postgresql"))
    {
        type = DB_TYPE_POSTGRESQL;
    }

    if(DB_TYPE_MAX == type)
    {
        printf("-t dbtype, Default to mysql{mysql\\oracle\\postgresql}\n");
        exit(1);
    }

    return type;
}

int sniffer_cfg_init(int argc,char **argv)
{
    int ret = 0;

    g_config.cap_ip = "127.0.0.1";
    g_config.cap_net = "eth0";
    g_config.cap_port = 3306;
    g_config.daemon = false;
    g_config.kafka = "127.0.0.1:9092";

    g_config.db_type = DB_TYPE_MYSQL;
    g_config.log_type = LOG_TYPE_WARN;

    g_config.object_id = 100;
    g_config.max_rowsets = 5;

    int opt = 0;
    while((opt = getopt(argc, argv, "dhi:p:s:t:l:k:b:r:")) != -1 && ret != -1){
        switch(opt){
            case 'd':
                {
                    g_config.daemon = true;
                    break;
                }
            case 'i':
                {
                    g_config.cap_net = optarg;
                    break;
                }
            case 'p':
                {
                    g_config.cap_port = atoi(optarg);
                    break;
                }
            case 's':
                {
                    g_config.cap_ip = optarg;
                    break;
                }
            case 't':
                {
                    g_config.db_type = cmdline_parse_dbtype(optarg);
                    break;
                }
            case 'l':
                {
                    g_config.log_type = cmdline_parse_logtype(optarg);
                    break;
                }
            case 'k':
                {
                    g_config.kafka = optarg;
                    break;
                }
            case 'b':
                {
                    g_config.object_id = atol(optarg);
                    break;
                }
            case 'r':
                {
                    g_config.max_rowsets = atol(optarg);
                    break;
                }

            case 'h':
            default:
                {
                    sniffer_help(argv[0]);
                    ret = -1;
                    break;
                }
        }
    }

    return ret;
}

sniffer_config * sniffer_cfg_get()
{
    return &g_config;
}

bool sniffer_cfg_daemon()
{
    return g_config.daemon;
}

LOG_TYPE sniffer_cfg_logtype()
{
    return g_config.log_type;
}

DB_TYPE sniffer_cfg_dbtype()
{
    return g_config.db_type;
}

string sniffer_cfg_capip()
{
    return g_config.cap_ip;
}

string sniffer_cfg_kafka()
{
    return g_config.kafka;
}

void sniffer_cfg_print()
{
    printf("+++++++++++++++++++++++++++++++++++++ \n"
        "sniffer config: \n"
        "       >interface %s \n"
        "       >port %d \n"
        "       >serverip %s \n"
        "       >daemon mode %d \n"
        "       >db type %d \n"
        "       >kafka address %s \n"
        "       >objectid %d \n"
        "       >max_rows %d \n"
        "+++++++++++++++++++++++++++++++++++++ \n"
        ,
        g_config.cap_net.c_str(),
        g_config.cap_port,
        g_config.cap_ip.c_str(),
        g_config.daemon,
        g_config.db_type,
        g_config.kafka.c_str(),
        g_config.object_id,
        g_config.max_rowsets);
}

uint32_t sniffer_cfg_max_rowset()
{
    return g_config.max_rowsets;
}

uint32_t sniffer_cfg_objectid()
{
    return g_config.object_id;
}
