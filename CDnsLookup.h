#pragma once

#define DNS_PORT	53	// DNS服务器端口

#pragma pack(push,1)
// QR
#define DNS_FLAGS_QR_REQUEST	0	// 查询
#define DNS_FLAGS_QR_RESPONSE	1	// 响应
// opcode
#define DNS_FLAGS_OPCODE_QUERY	0	// 标准查询
#define DNS_FLAGS_OPCODE_IQUERY	1	// 反向查询
#define DNS_FLAGS_OPCODE_STATUS	2	// 服务器状态查询
//#define DNS_FLAGS_OPCODE_UNDEFINE	3-15	// 保留值，暂时未使用
// RCODE
#define DNS_FLAGS_RCODE_NOERROR		0	// 没有错误
#define DNS_FLAGS_RCODE_FORMATERROR	1	// 报文格式错误(Format error) - 服务器不能理解请求的报文。
#define DNS_FLAGS_RCODE_SERVERFAIL	2	// 服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
#define DNS_FLAGS_RCODE_NAMEERROR	3	// 名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
#define DNS_FLAGS_RCODE_NOTIMPL		4	// 没有实现(Not Implemented) - 域名服务器不支持查询类型。
#define DNS_FLAGS_RCODE_REFUSED		5	// 拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。比如，服务器不希望对某些请求者给出应答，或者服务器不希望进行某些操作（比如区域传送zone transfer）。
//#define DNS_FLAGS_RCODE_UNDEFINE	6-15	// 保留值，暂时未使用

// DNS头部标志位
typedef struct _vDNS_HEADER_FLAGS
{
	WORD rcode : 4;	// 表示返回码，0无差错，1报文格式差错，2服务器失败，3名字错误，4没有实现，5拒绝，6-15 保留值
	WORD zero : 3;	// 保留字段
	WORD RA : 1;	// 支持递归， 这个比特位在应答中设置或取消，用来代表服务器是否支持递归查询
	WORD RD : 1;	// 被请求报文设置，该位为1表示客户端希望得到递归回答，应答时使用相同的值返回
	WORD TC : 1;	// 截断标志位。1表示响应已超过512字节并已被截断
	WORD AA : 1;	// 授权回答的标志位。该位在响应报文中有效，1表示域名服务器是权限服务器
	WORD opcode : 4;	// 定义查询或响应的类型（0为标准查询，1为反向查询，2为服务器状态请求，3-15保留值）
	WORD QR : 1;	// 查询/响应标志，0为查询，1为响应
	
}DNS_HEADER_FLAGS, *PDNS_HEADER_FLAGS;

// DNS头部
typedef struct _vDNS_HEADER
{
	WORD TransactionID;	// 会话标识
	DNS_HEADER_FLAGS Flags;	// 标志
	WORD Questions;		// 查询问题区域节的数量
	WORD AnswerRRs;		// 回答区域的数量
	WORD AuthorityRRs;	// 授权区域的数量
	WORD AdditionalRRs;	// 附加区域的数量
	BYTE Content[0];

}DNS_HEADER, *PDNS_HEADER;
#define DNS_HEADER_SIZE sizeof(DNS_HEADER)

// 查询类型
#define DNS_QUERY_TYPE_A		1	// 查询IPv4地址
#define DNS_QUERY_TYPE_NS		2	// 查询域名服务器
#define DNS_QUERY_TYPE_CNAME	5	// 查询规范名称
#define DNS_QUERY_TYPE_SOA		6	// 查询授权区域的开始
#define DNS_QUERY_TYPE_WKS		11	// 查询熟知服务描述
#define DNS_QUERY_TYPE_PTR		12	// 把IP地址转换成域名
#define DNS_QUERY_TYPE_HINFO	13	// 主机信息
#define DNS_QUERY_TYPE_MINFO	14	// 邮箱或邮件列表信息
#define DNS_QUERY_TYPE_MX		15	// 邮件交换
#define DNS_QUERY_TYPE_TXT		16	// 文字字串
#define DNS_QUERY_TYPE_AAAA		28	// 由域名获得IPv6地址
#define DNS_QUERY_TYPE_AXFR		252	// 传送整个区的请求
#define DNS_QUERY_TYPE_ANY		255	// 对所有记录的请求
// 查询协议类
#define DNS_QUERY_CLASS_IN	1	// 互联网
#define DNS_QUERY_CLASS_CH	3	// CHAOS类
#define DNS_QUERY_CLASS_HS	4	// Hesiod [Dyer 87]
#define DNS_QUERY_CLASS_ANY	255	// 所有类
// DNS查询问题
typedef struct _vDNS_QUESTION
{
	WORD Type;		// 查询类型
	WORD Class;		// 查询协议类
}DNS_QUESTION, *PDNS_QUESTION;
#define DNS_QUESTION_SIZE sizeof(DNS_QUESTION)

// 资源记录格式
typedef struct _vDNS_RESOURCE_RECORD
{
	WORD Type;		// 查询类型
	WORD Class;		// 查询协议类
	DWORD TTL;		// 生存时间
	WORD DataLength;	// 数据长度
	BYTE Data[0];	// 数据
}DNS_RESOURCE_RECORD, *PDNS_RESOURCE_RECORD;
#define DNS_RESOURCE_RECORD_SIZE sizeof(DNS_RESOURCE_RECORD)
#pragma pack(pop)

class CDnsLookup
{
public:
	CDnsLookup();
	~CDnsLookup();

	BOOL Lookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList);

private:
	BOOL UdpLookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList);
	BOOL TcpLookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList);

	BOOL UdpSend(SOCKET Socket, SOCKADDR_IN Addr, PVOID SendBase, DWORD SendSize);
	BOOL UdpRecv(SOCKET Socket, SOCKADDR_IN Addr, PVOID RecvBase, PDWORD RecvSize);
	BOOL TcpSend(SOCKET Socket, PVOID SendBase, DWORD SendSize);
	BOOL TcpRecv(SOCKET Socket, PVOID RecvBase, PDWORD RecvSize);

private:
	PDNS_HEADER GenerateRequestData(LPCSTR DomainName, PWORD DataSize);
	std::vector<std::string> Split(std::string SourceStr, std::string SplitStr);
	DWORD DecodeDomainName(PDNS_HEADER DnsHeader, DWORD OffsetRead, std::string& DomainName);
	BOOL AnalyzeData(PDNS_HEADER DnsHeader, std::map<std::string, std::string>& ResultIpList);

private:
	static const int s_Timeout = 5000;
};