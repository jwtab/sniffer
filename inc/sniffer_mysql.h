
#ifndef SNIFFER_MYSQL_H_H_
#define SNIFFER_MYSQL_H_H_

#include <sniffer_inc.h>
#include <sniffer_sess.h>

/*
    int<3> Packet length(payload len) 不包括头4字节.
    int<1> Packet number
*/
const short MYSQL_HEAD_LEN = 4;

//MySQL protocol token.
enum MYSQL_TEXT_PROTOCOL{
	COM_SLEEP                = 0x00,
	COM_QUIT                 = 0x01,
	COM_INIT_DB              = 0x02,
	COM_QUERY                = 0x03,
	COM_FIELD_LIST           = 0x04,
	COM_CREATE_DB            = 0x05,
	COM_DROP_DB              = 0x06,
	COM_REFRESH              = 0x07,
	COM_SHUTDOWN             = 0x08,
	COM_STATISTICS           = 0x09,
	COM_PROCESS_INFO         = 0x0a,
	COM_CONNECT              = 0x0b,
	COM_PROCESS_KILL         = 0x0c,
	COM_DEBUG                = 0x0d,
	COM_PING                 = 0x0e,
	COM_TIME                 = 0x0f,
	COM_DELAYED_INSERT       = 0x10,
	COM_CHANGE_USER          = 0x11,
	COM_BINLOG_DUMP          = 0x12,
	COM_TABLE_DUMP           = 0x13,
	COM_CONNECT_OUT          = 0x14,
	COM_REGISTER_SLAVE       = 0x15,
	COM_STMT_PREPARE         = 0x16,
	COM_STMT_EXECUTE         = 0x17,
	COM_STMT_SEND_LONG_DATA  = 0x18,
	COM_STMT_CLOSE           = 0x19,
	COM_STMT_RESET           = 0x1a,
	COM_SET_OPTION           = 0x1b,
	COM_STMT_FETCH           = 0x1c,
	COM_DAEMON               = 0x1d,
	COM_BINLOG_DUMP_GTID     = 0x1e,

	//自定义
	COM_UNKNOWN              = 0x20,
	COM_LOGIN                = 0x21,
	COM_LOAD_DATA_INFILE     = 0x22,
    COM_MAX
};

//client capability flag.
enum MYSQL_CLIENT_CAPA_FLAG{
	CLIENT_LONG_PASSWORD                = 0x00000001,
	CLIENT_FOUND_ROWS                   = 0x00000002,
	CLIENT_LONG_FLAG                    = 0x00000004,
	CLIENT_CONNECT_WITH_DB              = 0x00000008,
	CLIENT_NO_SCHEMA                    = 0x00000010,
	CLIENT_COMPRESS                     = 0x00000020,
	CLIENT_ODBC                         = 0x00000040,
	CLIENT_LOCAL_FILES                  = 0x00000080,
	CLIENT_IGNORE_SPACE                 = 0x00000100,
	CLIENT_PROTOCOL_41                  = 0x00000200,
	CLIENT_INTERACTIVE                  = 0x00000400,
	CLIENT_SSL                          = 0x00000800,
	CLIENT_IGNORE_SIGPIPE               = 0x00001000,
	CLIENT_TRANSACTIONS                 = 0x00002000,
	CLIENT_RESERVED                     = 0x00004000,
	CLIENT_SECURE_CONNECTION            = 0x00008000,
	CLIENT_MULTI_STATEMENTS             = 0x00010000,
	CLIENT_NULTI_RESULTS                = 0x00020000,
	CLIENT_PS_MULTI_RESULTS             = 0x00040000,
	CLIENT_PLUGIN_AUTH                  = 0x00080000,
	CLIENT_CONNECT_ATTRS                = 0x00100000,
	CLIENT_PLUGIN_AUTH_LENENCODENT_DATA = 0x00200000,
};

//Data variable type.
enum MYSQL_VARIABLE_TYPE{
	MYSQL_TYPE_DECIMAL     = 0x00,
	MYSQL_TYPE_TINY        = 0x01,
	MYSQL_TYPE_SHORT       = 0x02,
	MYSQL_TYPE_LONG        = 0x03,
	MYSQL_TYPE_FLOAT       = 0x04,
	MYSQL_TYPE_DOUBLE      = 0x05,
	MYSQL_TYPE_NULL        = 0x06,
	MYSQL_TYPE_TIMESTAMP   = 0x07,
	MYSQL_TYPE_LONGLONG    = 0x08,
	MYSQL_TYPE_INT24       = 0x09,
	MYSQL_TYPE_DATE        = 0x0a,
	MYSQL_TYPE_TIME        = 0x0b,
	MYSQL_TYPE_DATETIME    = 0x0c,
	MYSQL_TYPE_YEAR        = 0x0d,
	MYSQL_TYPE_NEWDATE     = 0x0e,
	MYSQL_TYPE_VARCHAR     = 0x0f,
	MYSQL_TYPE_BIT         = 0x10,
	MYSQL_TYPE_NEWDECIMAL  = 0xf6,
	MYSQL_TYPE_ENUM        = 0xf7,
	MYSQL_TYPE_SET         = 0xf8,
	MYSQL_TYPE_TINY_BLOB   = 0xf9,
	MYSQL_TYPE_MEDIUM_BLOB = 0xfa,
	MYSQL_TYPE_LONG_BLOB   = 0xfb,
	MYSQL_TYPE_BLOB        = 0xfc,
	MYSQL_TYPE_VAR_STRING  = 0xfd,
	MYSQL_TYPE_STRING      = 0xfe,
	MYSQL_TYPE_GEOMETRY    = 0xff,
};

//binlog flag.
enum MYSQL_BINLOG_FLAG{
	BINLOG_DUMP_NON_BLOCK   = 0x01,
	BINLOG_THROUGH_POSITION = 0x02,
	BINLOG_THROUGH_GTID     = 0x04
};

enum MYSQL_CMD_STATUS{
	MYSQL_CMD_CONNECTION_PHASE = 0x00,
	MYSQL_CMD_COMMAND_PHASE,
	MYSQL_CMD_REPLICATION,
	MYSQL_CMD_MAX
};

/*
                非SSL登录认证过程
    +++++++++++++++++++++++++++++++++++++++++++++++++++
        Client                          Server
    +++++++++++++++++++++++++++++++++++++++++++++++++++
   1>                       <----       Server Greeting[HandshakeV10/V9]
   2>     Login Request     ---->
  -3>                       <----       Auth Switch Request
  -4> Auth Switch Response  ---> 
   5>                       <---        Response OK

                SQL请求与处理
    +++++++++++++++++++++++++++++++++++++++++++++
        Client                    Server            
    +++++++++++++++++++++++++++++++++++++++++++++
    1>    Request Query    --->
    2>                     <---    Response
    .>                     <---    Response
*/


typedef struct st_mysql
{
    //保存mysql客户端能力值
    uint32_t capabilities;
    bool     compressed;
    bool     ssl;
    bool     isHandshakeV10;
    bool     isProtocolV41;

    bool query;
	enum MYSQL_TEXT_PROTOCOL cmd_type;

    //上下行数据.
    struct sniffer_buf * downstream_buf;
	uint32_t seq_number;
	uint32_t packet_len;

	uint32_t columns_select;
	uint32_t columns_select_index;

	uint32_t affect_rows;

	//绑定变量
	uint32_t statement_id;
	uint32_t num_params;
	uint32_t num_columns;
	uint16_t num_columns_index;
	uint16_t *columns_select_type;


}ST_MTSQL;

int dispatch_data_mysql(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_mysql_upstream(sniffer_session *session,const char * data,uint32_t data_len);
int dispatch_data_mysql_downstream(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_mysql_downstream_err_packet(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_mysql_parseHead(struct st_mysql *mysql,struct sniffer_buf *buf);

uint32_t dispatch_mysql_DDL_Reponse(struct sniffer_buf *buf,uint32_t offset);

uint32_t dispatch_mysql_ResultsetRow(sniffer_session *session);
uint32_t dispatch_mysql_ResultsetRow_Stmt(sniffer_session *session);
uint32_t dispatch_mysql_ResultsetRow_ColumnDefinition(sniffer_session *session);

#endif //SNIFFER_MYSQL_H_H_
