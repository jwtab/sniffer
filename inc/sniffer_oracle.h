
#ifndef SNIFFER_ORACLE_H_H_
#define SNIFFER_ORACLE_H_H_

#include <sniffer_inc.h>
#include <sniffer_sess.h>

/*
    int<2> Packet length 包括头
    int<2> Pakcet checksum 0x00 0x00
    int<1> Packet type
    int<1> Revered byte
    int<2> Header checksum 0x00 0x00 
*/

#define ORACLE_HEAD_LEN 8
#define G_ROWID_TABLE_LEN 64

#define ORA_ROWID_64_0 0
#define ORA_ROWID_64_1 64
#define ORA_ROWID_64_2 4096
#define ORA_ROWID_64_3 262144UL
#define ORA_ROWID_64_4 16777216UL
#define ORA_ROWID_64_5 1073741824UL

/*
    TNS packet type.
*/
enum TNS_PACKET_TYPE {
    TNS_TYPE_Unkown = 0x00,
    TNS_TYPE_CONNECT,
    TNS_TYPE_ACCEPT,
    TNS_TYPE_ACK,
    TNS_TYPE_REFUSE,
    TNS_TYPE_REDIRECT,
    TNS_TYPE_DATA,
    TNS_TYPE_NULL,
    TNS_TYPE_UNK1,
    TNS_TYPE_ABORT,
    TNS_TYPE_UNK2,
    TNS_TYPE_RESEND,
    TNS_TYPE_MARKER,
    TNS_TYPE_ATTENTION,
    TNS_TYPE_CONTROL,
    TNS_TYPE_MAX
};

enum TNS_0x03_0x5e_Len_Type {
    TNS_0x03_0x5e_Len_0 = 0x00,
    TNS_0x03_0x5e_Len_1 = 0x01,
    TNS_0x03_0x5e_Len_2 = 0x02
};

enum TNS_COLUMN_TYPE {
    TNS_COLUMN_TYPE_UNKNOWN		    = 0x00,
	TNS_COLUMN_TYPE_VARCHAR2		= 0x01,
	TNS_COLUMN_TYPE_NUMBER			= 0x02,
	TNS_COLUMN_TYPE_ROWNUM			= 0x06,
	TNS_COLUMN_TYPE_LONG			= 0x08,
	TNS_COLUMN_TYPE_ROWID			= 0x0b,
	TNS_COLUMN_TYPE_DATE			= 0x0c,
	TNS_COLUMN_TYPE_SDO_DIM_ELEMENT = 0x17,
	TNS_COLUMN_TYPE_CHAR			= 0x60,
	TNS_COLUMN_TYPE_BINARY_FLOAT	= 0x64,
	TNS_COLUMN_TYPE_BINARY_DOUBLE	= 0x65,
	TNS_COLUMN_TYPE_SDO_DIM_ARRAY	= 0x6d,
	TNS_COLUMN_TYPE_CLOB			= 0x70,
	TNS_COLUMN_TYPE_BLOB			= 0x71,
	TNS_COLUMN_TYPE_BFILE			= 0x72,
	TNS_COLUMN_TYPE_TIMESTAMP		= 0xb4
};

/*
    tns header.
*/
typedef struct tns_header
{
    /*
        大端序   ntohs转换.
    */
    unsigned short packet_len:16;

    unsigned short packet_checksum:16;

    unsigned short packet_type:8;
    
    unsigned short rsrvd:8;
    unsigned short header_checksum:16;
}TNS_HEADER,*LPTNS_HEADER;

/*
    tns connect.
*/
typedef struct tns_connect
{
    unsigned short client_version:16;
    unsigned short client_version_Compatible:16;
    unsigned short service_options:16;
    unsigned short client_SDU:16;
    unsigned short client_TDU:16;
    unsigned short nt_protocol:16;
    unsigned short line_value:16;

    /*
        客户端端序列标识
            0x0001 大端序[当前包不会受到该字段的影响, 全部都是大端序编码]
    */
    unsigned short client_hardware:16;

    /*
        连接字符串的长度.
    */
    unsigned short connect_data_len:16;

    /*
        连接字符串起始位置，相对于tns_header的开始位置.
    */
    unsigned short connect_data_pos:16;

    /*
        其它若干变量.
    */
}TNS_CONNECT,*LPTNS_CONNECT;


/*
                        单机模式过程
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
            Client                  Server
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
   1>        Connect     --->
   2>                    <---      Resend
   3>        Connect     --->      
   4>                    <---      Accept  
    

                        RAC模式过程
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
            Client                  Server
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
   1>        Connect     --->
   2>                    <---       Redirect
   3>        Connect     --->
   4>                    <---       Accept

                        协商登录过程
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
            Client                  Server
    ++++++++++++++++++++++++++++++++++++++++++++++++++++
   1>    Data(SNS)        --->
   2>                     <---     Data(Secure Network Service)
   ... SNS 可能会重复多次.
   3>    Data(0x01)       --->
   4>                     <---     Data(Set Protocol) 0x01
   5>    Data(0x02)       --->
   6>                     <---     Data(Set Datatypes) 0x02
   7>    Data(0x0376)     --->                            
   8>                     <---     Data(0x08)
   9>    Data(0x0373)     --->
   10>                    <---     Data(0x08)

   *** 1、2相同； 3、4相同； 5、6相同。 7、8、9、10是登录认证的过程，7包含用户名，9包含登录密码.
        3、4包含服务器端和客户端协议版本信息.

*/


typedef struct st_oracle
{
    struct sniffer_buf * upstream_buf;
    struct sniffer_buf * downstream_buf;

    uint8_t from_upstream;

    //TNS_HEADER 要提前转化位主机字节序.
    struct tns_header _tns_header;

    //具体请求类型.
    uint16_t dataID_query;
    uint16_t callID_query;
    
    //结果集信息.
    uint32_t affect_rows;
    uint32_t max_rowset;
	cJSON * select_body;

    uint8_t fetch_a_row;

    uint32_t columns_select;
    uint16_t *columns_select_type;
    struct sniffer_buf **columns_select_name;
}ST_ORACLE,*LPST_ORACLE;

/*
    对外函数.
*/
int dispatch_data_oracle(sniffer_session *session,const char * data,uint32_t data_len);
uint32_t xProxy_oracle_upstream(struct sniffer_session *session, const char * payload,uint32_t payload_len);
uint32_t xProxy_oracle_downstream(struct sniffer_session *session, const char * payload,uint32_t payload_len);

/*
    功能辅助函数.
*/

/*
	解析Oracle协议头.
*/
uint32_t xProxy_oracle_ParseHead(struct st_oracle * oracle,struct xProxy_buf * buf);

void xProxy_oracle_TNS_Connect(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data(struct sniffer_session *session,uint32_t offset);

void xProxy_oracle_TNS_Accept(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Redirect(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Resend(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Refuse(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Marker(struct sniffer_session *session,uint32_t offset);

void xProxy_oracle_TNS_Data_0x01(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x02(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x04(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x06(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x08(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x09(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x10(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x10_1(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x10_2(struct sniffer_session *session,uint32_t offset);
uint32_t xProxy_oracle_TNS_Data_0x10_DATA(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x11(struct sniffer_session *session,uint32_t offset);

void xProxy_oracle_TNS_Data_0x03_0x05(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x0e(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x3b(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x76(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x73(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x5e(struct sniffer_session *session,uint32_t offset);
void xProxy_oracle_TNS_Data_0x03_0x5e_Len_0(struct sniffer_session *session,uint32_t offset);

void xProxy_oracle_TNS_Data_0x03_0x4e(struct sniffer_session *session,uint32_t offset);

//
void xProxy_oracle_DataAnalyse(struct sniffer_buf* data_src,enum TNS_COLUMN_TYPE data_type,struct sniffer_buf *data_string);

void xProxy_db_oracle_ROWID(struct sniffer_buf * src,struct sniffer_buf*str,int mode);

#endif //SNIFFER_ORACLE_H_H_
