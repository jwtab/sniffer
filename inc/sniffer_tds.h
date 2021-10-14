
#ifndef SNIFFER_TDS_H_H_
#define SNIFFER_TDS_H_H_

#include <sniffer_inc.h>
#include <sniffer_sess.h>

/*
    TDS包头大小.
*/
const short TDS_HEAD_LEN = 8;

//TDS包类型定义.
enum TDS_TYPE{
	TDS_TYPE_SQLBATCH		    = 0x01,	//SQL batch
	TDS_TYPE_PRETDS7 		    = 0x02,	//Pre-login TDS7
	TDS_TYPE_RPC				= 0x03,	//remote procedure call
	TDS_TYPE_TABULARRESULT	    = 0x04,	//tabular result
	TDS_TYPE_ATTENTION		    = 0x06,	//attention signal
	TDS_TYPE_BULK				= 0x07,	//bulk load data
	TDS_TYPE_TRANSACTION	    = 0x0e,	//transaction manager request
	TDS_TYPE_LOGIN7			    = 0x10,	//login
	TDS_TYPE_SSPI				= 0x11,	//SSPI message
	TDS_TYPE_PRELOGIN		    = 0x12	//Pre-Login message
};

//TDS包类型标记.
enum TDS_DATA_TOKEN{
	TDS_TOKEN_TVPROW			= 0x01,
	TDS_TOKEN_OFFSET			= 0x78,
	TDS_TOKEN_RETURNSTATUS	    = 0x79,
	TDS_TOKEN_COLMETADATA		= 0x81,
	TDS_TOKEN_ALTMETADATA		= 0x88,
	TDS_TOKEN_TABNAME			= 0xa4,
	TDS_TOKEN_COLINFO			= 0xa5,
	TDS_TOKEN_ORDER				= 0xa9,
	TDS_TOKEN_ERROR				= 0xaa,
	TDS_TOKEN_INFO				= 0xab,
	TDS_TOKEN_RETURNVALUE		= 0xac,
	TDS_TOKEN_LOGINACK			= 0xad,
	TDS_TOKEN_ROW				= 0xd1,
	TDS_TOKEN_NBCROW			= 0xd2,
	TDS_TOKEN_ALTROW			= 0xd3,
	TDS_TOKEN_ENVCHANGE		    = 0xe3,
	TDS_TOKEN_SSPI				= 0xed,
	TDS_TOKEN_DONE				= 0xfd,
	TDS_TOKEN_DONEPROC			= 0xfe,
	TDS_TOKEN_DONEINPROC		= 0xff,
};

//TDS数据类型定义.
enum MSSQL_VARI_TYPE{
	TDS_DATA_UNKNOWN			    = 0x00,
	TDS_DATA_NULL					= 0x1F, //Null
	TDS_DATA_IMAGE					= 0x22, //Image
	TDS_DATA_TEXT					= 0x23, //Text
	TDS_DATA_GUID					= 0x24, //UniqueIdentifier
	TDS_DATA_VARBINARY				= 0x25, //VarBinary (legacy support)
	TDS_DATA_INTN					= 0x26, //int(n)
	TDS_DATA_VARCHAR				= 0x27, //VarChar (legacy support)
	TDS_DATA_DATEN					= 0x28, //(introduced in TDS 7.3)
	TDS_DATA_TIMEN					= 0x29, //(introduced in TDS 7.3)
	TDS_DATA_DATETIME2N			    = 0x2A, //(introduced in TDS 7.3)
	TDS_DATA_DATETIMEOFFSETN		= 0x2B, //(introduced in TDS 7.3)
	TDS_DATA_BINARY				    = 0x2D, //Binary (legacy support)
	TDS_DATA_CHAR					= 0x2F, //Char (legacy support)
	TDS_DATA_TINYINT				= 0x30, //TinyInt
	TDS_DATA_BIT					= 0x32, //Bit
	TDS_DATA_SMALLINT				= 0x34, //SmallInt
	TDS_DATA_DECIMAL				= 0x37, //Decimal (legacy support)
	TDS_DATA_INT					= 0x38, //Int
	TDS_DATA_SMALLDATETIME			= 0x3A, //SmallDateTime
	TDS_DATA_REAL					= 0x3B, //Real
	TDS_DATA_MONEY					= 0x3C, //Money
	TDS_DATA_DATETIME				= 0x3D, //DateTime
	TDS_DATA_FLOAT					= 0x3E, //Float
	TDS_DATA_NUMERIC				= 0x3F, //Numeric (legacy support)
	TDS_DATA_SQLVARIANT 			= 0x62, //Sql_Variant (introduced in TDS 7.2)
	TDS_DATA_NTEXT					= 0x63, //NText
	TDS_DATA_BITN					= 0x68, //bit(n)
	TDS_DATA_DECIMALN				= 0x6A, //Decimal
	TDS_DATA_NUMERICN				= 0x6C, //Numeric
	TDS_DATA_FLOATN				    = 0x6D, //float(n)
	TDS_DATAL_MONEYN				= 0x6E, //(see below)
	TDS_DATA_DATETIMEN				= 0x6F, //datetime(n)
	TDS_DATA_SMALLMONEY			    = 0x7A, //SmallMoney
	TDS_DATA_BIGINT				    = 0x7F, //BigInt
	TDS_DATA_VARBINARYN			    = 0xA5, //VarBinary
	TDS_DATA_VARCHARN				= 0xA7, //VarChar(n)
	TDS_DATA_BINARYN				= 0xAD, //Binary(n),可以存放timestamp,rowversion
	TDS_DATA_CHARN					= 0xAF, //Char(n)
	TDS_DATA_NVARCHAR				= 0xE7, //NVarChar
	TDS_DATA_NCHAR					= 0xEF, //NChar
	TDS_DATA_UDT					= 0xF0, //CLR-UDT (introduced in TDS 7.2)
	TDS_DATA_XML					= 0xF1  //XML (introduced in TDS 7.2)
};

/*
    tds header.
*/
typedef struct tds_header
{
    unsigned char tds_type:8;

    unsigned char status:8;

    unsigned short packet_len:16; //包括tds_header.
    
    unsigned short channel:16;

    unsigned char packet_number:8;

    unsigned char window:8;
}TDS_HEADER,*LPTDS_HEADER;

//st上下文对象.
typedef struct st_tds
{
    struct sniffer_buf * downstream_buf;
    struct sniffer_buf * upstream_buf;

    struct tds_header header;
}ST_TDS;

int dispatch_data_tds(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_tds_upstream(sniffer_session *session,const char * data,uint32_t data_len);
int dispatch_data_tds_downstream(sniffer_session *session,const char * data,uint32_t data_len);

int dispatch_data_tds_parseHead(struct st_tds *tds,struct sniffer_buf *buf);

void dispatch_TDS_SQLBATCH(struct sniffer_session *session,uint32_t offset);
void dispatch_TDS_PRELOGIN(struct sniffer_session *session,uint32_t offset);
void dispatch_TDS_TABULARRESULT(struct sniffer_session *session,uint32_t offset);
void dispatch_TDS_TRANSACTION(struct sniffer_session *session,uint32_t offset);
void dispatch_TDS_RPC(struct sniffer_session *session,uint32_t offset);

#endif //SNIFFER_TDS_H_H_
