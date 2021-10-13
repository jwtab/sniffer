
#include <sniffer_log.h>
#include <sniffer_cfg.h>
#include <sniffer_buf.h>

#include <librdkafka/rdkafka.h>

static char DB_TYPE_string[DB_TYPE_MAX][64] = 
{
    "Unkown",
    "MySQL",
    "MariaDB",
    "GBase 8a",
    "Oracle",
    "PostgreSQL",
    "Greenplum"
    "DM",
    "Informix",
    "GBase 8s",
    "GBase 8t",
    "Hive",
    "MSSQL"
};

static char LOG_TYPE_string[LOG_TYPE_MAX][12] = 
{
    "FATAL",
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG"
};

static rd_kafka_t *g_rd_kafka;            /*Producer instance handle*/
static rd_kafka_topic_t *g_rd_kafka_topic;     /*topic对象*/

static uint64_t g_kafka_log_cnt = 0;
static string g_agent_uid = "EFBDCC0E5BBC";

static string sniffer_base64_encode(string plain_text)
{
    uint32_t plain_len = plain_text.length();
    uint32_t base64_len = plain_len*1.5;
    string encoder = "";

    char * base64 = (char*)zmalloc(base64_len);
    if(base64)
    {
        memset(base64,0,base64_len);

        string cmd_line = "echo '" + plain_text;
        cmd_line = cmd_line + "'|base64 -i -w 0";
        
        FILE * file = popen(cmd_line.c_str(),"r");
        if(file)
        {
            fread(base64,1,base64_len,file);

            fclose(file);
            file = nullptr;

            encoder = base64;
        }

        zfree(base64);
        base64 = nullptr;
    }

    return encoder;
}

static void sniffer_log_msg_cb(rd_kafka_t *rk,const rd_kafka_message_t *rkmessage, void *opaque)
{
	if(rkmessage->err)
	{
        ERROR_LOG("sniffer_log.cpp:sniffer_log_msg_cb() Message delivery failed: %s\n",rd_kafka_err2str(rkmessage->err));
    }
	else
	{
        DEBUG_LOG("sniffer_log.cpp:sniffer_log_msg_cb() Message delivered %d bytes",rkmessage->len);
    }
}

void sniffer_log(LOG_TYPE t,const char * format,...)
{
    char log[4096] = {0};
    va_list stArgs;

    if(t > sniffer_cfg_logtype())
    {
        return;
    }

    va_start(stArgs, format);
    vsnprintf(log,4096,format, stArgs);

    printf("[%s] %s %s\n",sniffer_current_time().c_str(),LOG_TYPE_string[t],log);

    va_end(stArgs);
}

void sniffer_kafka_log(const char * log,uint32_t log_len)
{
    INFO_LOG("sniffer_log.cpp:sniffer_kafka_log() %s",log);

    if(g_rd_kafka_topic && g_rd_kafka)
    {
        if (-1 == rd_kafka_produce(g_rd_kafka_topic,RD_KAFKA_PARTITION_UA,RD_KAFKA_MSG_F_COPY,(void*)log,log_len,NULL, 0,NULL))
        {
     		ERROR_LOG("sniffer_log.cpp:sniffer_kafka_log() Failed to produce to topic %s: %s", 
     			rd_kafka_topic_name(g_rd_kafka_topic),
     			rd_kafka_err2str(rd_kafka_last_error()));
 
     		if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL)
            {
                /*如果内部队列满，等待消息传输完成并retry,
                内部队列表示要发送的消息和已发送或失败的消息，
                内部队列受限于queue.buffering.max.messages配置项*/
     			rd_kafka_poll(g_rd_kafka,1000);
            }
     	}
        else
        {
     		DEBUG_LOG("sniffer_log.cpp:sniffer_kafka_log() Enqueued message (%d bytes) for topic %s", 
     			log_len, rd_kafka_topic_name(g_rd_kafka_topic));
     	}

        int cnt = rd_kafka_poll(g_rd_kafka, 0);
        DEBUG_LOG("sniffer_log.cpp:sniffer_kafka_log() rd_kafka_poll(%s) cnt %d",rd_kafka_topic_name(g_rd_kafka_topic),cnt);
    }
}

int sniffer_kafka_init()
{
    rd_kafka_conf_t * conf = rd_kafka_conf_new();

    char errstr[512] = {0};

    //broker集群
	if (rd_kafka_conf_set(conf,"bootstrap.servers",sniffer_cfg_kafka().c_str(),errstr,512) != RD_KAFKA_CONF_OK)
    {
		ERROR_LOG("sniffer_log.cpp:sniffer_kafka_init() rd_kafka_conf_set() error %s",errstr);
		return 1;
	}

    rd_kafka_conf_set_dr_msg_cb(conf,sniffer_log_msg_cb);
    
    //认证的用户名+密码.

    g_rd_kafka = rd_kafka_new(RD_KAFKA_PRODUCER,conf,errstr,512);
	if(!g_rd_kafka)
    {
		ERROR_LOG("sniffer_log.cpp:sniffer_kafka_init() rd_kafka_new() error %s",errstr);
		return 1;
	}

    rd_kafka_brokers_add(g_rd_kafka,sniffer_cfg_kafka().c_str());

    //加一个topic.
    g_rd_kafka_topic = rd_kafka_topic_new(g_rd_kafka,"sqllog", NULL);
	if(!g_rd_kafka_topic)
    {
        ERROR_LOG("sniffer_log.cpp:sniffer_kafka_init() rd_kafka_topic_new() error %s",rd_kafka_err2str(rd_kafka_last_error()));
        
		rd_kafka_destroy(g_rd_kafka);
		return 1;
	}

    return 0;
}

void sniffer_kafka_body(cJSON * body)
{
    cJSON * root = cJSON_CreateObject();
    if(!root)
    {
        return;
    }

    string from_str = "_client.httplog_notify." + g_agent_uid;
    string request_id = from_str + "_";
    request_id = request_id + to_string(g_kafka_log_cnt);

    cJSON_AddItemToObject(root,"body",cJSON_CreateString(sniffer_base64_encode(cJSON_PrintUnformatted(body)).c_str()));

    cJSON_AddItemToObject(root,"from",cJSON_CreateString(from_str.c_str()));

    cJSON * to_array = cJSON_CreateArray();
    if(!to_array)
    {
        return;
    }

    cJSON_AddItemToArray(to_array,cJSON_CreateString("httplog_notify"));
    cJSON_AddItemToObject(root,"to",to_array);

    cJSON *headers = cJSON_CreateObject();
    if(!headers)
    {
        return;
    }

    cJSON_AddItemToObject(headers,"expire",cJSON_CreateString(to_string(sniffer_log_time_ms() + 2000).c_str()));
    cJSON_AddItemToObject(headers,"content-type",cJSON_CreateString("event"));
    cJSON_AddItemToObject(headers,"cdc",cJSON_CreateString("sh"));

    cJSON_AddItemToObject(root,"headers",headers);

    cJSON_AddItemToObject(root,"requestid",cJSON_CreateString(request_id.c_str()));

    cJSON * reply_array = cJSON_CreateArray();
    if(!reply_array)
    {
        return;
    }

    cJSON_AddItemToArray(reply_array,cJSON_CreateString(from_str.c_str()));
    cJSON_AddItemToObject(root,"reply",reply_array);

    char * kafka_body = cJSON_PrintUnformatted(root);
    if(kafka_body)
    {
        sniffer_kafka_log(kafka_body,strlen(kafka_body));

        free(kafka_body);
        kafka_body = nullptr;
    }

    cJSON_Delete(root);

    g_kafka_log_cnt++;
}

void sniffer_kafka_uninit()
{
    if(g_rd_kafka && g_rd_kafka_topic)
    {
        rd_kafka_flush(g_rd_kafka,10*1000);
 
        rd_kafka_topic_destroy(g_rd_kafka_topic);
        rd_kafka_destroy(g_rd_kafka);
    }
}

string sniffer_current_time()
{
    string time_format = "";

    struct timeval tv;
    struct tm* ptm;
    char time_string[60] = {0};
    long milliseconds;
    
    gettimeofday(&tv, NULL);

    ptm = localtime(&(tv.tv_sec));

    //从微秒计算毫秒
    milliseconds = tv.tv_usec/1000;
 
    //以秒为单位打印格式化后的时间日期，小数点后为毫秒。
    snprintf(time_string,60,"%d-%02d-%02d %02d:%02d:%02d.%03ld",
            ptm->tm_year + 1900,ptm->tm_mon + 1,ptm->tm_mday,
            ptm->tm_hour,ptm->tm_min,ptm->tm_sec,
            milliseconds);

    time_format = time_string;

    return time_format;
}

void sniffer_log_uuid(char * uuid)
{
    string cmd_line = "uuidgen";

    FILE * file = popen(cmd_line.c_str(),"r");
    if(file)
    {
        fread(uuid,1,36,file);

        fclose(file);

        return;
    }

    ERROR_LOG("sniffer_sess.cpp:sniffer_session_uuid() error error_code %d",errno);

    strcpy(uuid,"74A84ACC-3756-42DF-8652-1E3799D65353");
}

char * sniffer_DB_TYPE_string(DB_TYPE t)
{
    return DB_TYPE_string[t];
}

uint64_t sniffer_log_time_ms()
{
    struct timeval tv;
    uint64_t current_ms = 0;

    gettimeofday(&tv, NULL);

    current_ms = tv.tv_sec*1000 + tv.tv_usec;

    return current_ms;
}
