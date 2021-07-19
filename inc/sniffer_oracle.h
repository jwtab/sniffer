
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

const uint16_t ORACLE_HEAD_LEN = 8;

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
    bool query;

    //上下行数据.
}ST_ORACLE;

int dispatch_data_oracle(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_oracle_upstream(sniffer_session *session,const char * data,uint32_t data_len);
int dispatch_data_oracle_downstream(sniffer_session *session,const char * data,uint32_t data_len);

//辅助函数.
//upstream 去掉头的数据和对应的长度.
void Dump_TNS_Connect(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data(sniffer_session *session,const char * data,uint32_t len);

void Dump_TNS_Data_0x01(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x02(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x03(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x11(sniffer_session *session,const char * data,uint32_t len);

void Dump_TNS_Data_0x03_0x76(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x03_0x73(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x03_0x5e(sniffer_session *session,const char * data,uint32_t len);
void Dump_TNS_Data_0x03_0x5e_Len_0(sniffer_session *session,const char * data,uint32_t len);

void Dump_TNS_Data_0x03_0x4e(sniffer_session *session,const char * data,uint32_t len);

#endif //SNIFFER_ORACLE_H_H_
