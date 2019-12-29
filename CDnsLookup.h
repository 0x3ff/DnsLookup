#pragma once

#define DNS_PORT	53	// DNS�������˿�

#pragma pack(push,1)
// QR
#define DNS_FLAGS_QR_REQUEST	0	// ��ѯ
#define DNS_FLAGS_QR_RESPONSE	1	// ��Ӧ
// opcode
#define DNS_FLAGS_OPCODE_QUERY	0	// ��׼��ѯ
#define DNS_FLAGS_OPCODE_IQUERY	1	// �����ѯ
#define DNS_FLAGS_OPCODE_STATUS	2	// ������״̬��ѯ
//#define DNS_FLAGS_OPCODE_UNDEFINE	3-15	// ����ֵ����ʱδʹ��
// RCODE
#define DNS_FLAGS_RCODE_NOERROR		0	// û�д���
#define DNS_FLAGS_RCODE_FORMATERROR	1	// ���ĸ�ʽ����(Format error) - �����������������ı��ġ�
#define DNS_FLAGS_RCODE_SERVERFAIL	2	// ������ʧ��(Server failure) - ��Ϊ��������ԭ����û�취�����������
#define DNS_FLAGS_RCODE_NAMEERROR	3	// ���ִ���(Name Error) - ֻ�ж���Ȩ�������������������壬ָ�����������������ڡ�
#define DNS_FLAGS_RCODE_NOTIMPL		4	// û��ʵ��(Not Implemented) - ������������֧�ֲ�ѯ���͡�
#define DNS_FLAGS_RCODE_REFUSED		5	// �ܾ�(Refused) - �������������õĲ��Ծܾ�����Ӧ�𡣱��磬��������ϣ����ĳЩ�����߸���Ӧ�𣬻��߷�������ϣ������ĳЩ����������������zone transfer����
//#define DNS_FLAGS_RCODE_UNDEFINE	6-15	// ����ֵ����ʱδʹ��

// DNSͷ����־λ
typedef struct _vDNS_HEADER_FLAGS
{
	WORD rcode : 4;	// ��ʾ�����룬0�޲��1���ĸ�ʽ���2������ʧ�ܣ�3���ִ���4û��ʵ�֣�5�ܾ���6-15 ����ֵ
	WORD zero : 3;	// �����ֶ�
	WORD RA : 1;	// ֧�ֵݹ飬 �������λ��Ӧ�������û�ȡ������������������Ƿ�֧�ֵݹ��ѯ
	WORD RD : 1;	// �����������ã���λΪ1��ʾ�ͻ���ϣ���õ��ݹ�ش�Ӧ��ʱʹ����ͬ��ֵ����
	WORD TC : 1;	// �ضϱ�־λ��1��ʾ��Ӧ�ѳ���512�ֽڲ��ѱ��ض�
	WORD AA : 1;	// ��Ȩ�ش�ı�־λ����λ����Ӧ��������Ч��1��ʾ������������Ȩ�޷�����
	WORD opcode : 4;	// �����ѯ����Ӧ�����ͣ�0Ϊ��׼��ѯ��1Ϊ�����ѯ��2Ϊ������״̬����3-15����ֵ��
	WORD QR : 1;	// ��ѯ/��Ӧ��־��0Ϊ��ѯ��1Ϊ��Ӧ
	
}DNS_HEADER_FLAGS, *PDNS_HEADER_FLAGS;

// DNSͷ��
typedef struct _vDNS_HEADER
{
	WORD TransactionID;	// �Ự��ʶ
	DNS_HEADER_FLAGS Flags;	// ��־
	WORD Questions;		// ��ѯ��������ڵ�����
	WORD AnswerRRs;		// �ش����������
	WORD AuthorityRRs;	// ��Ȩ���������
	WORD AdditionalRRs;	// �������������
	BYTE Content[0];

}DNS_HEADER, *PDNS_HEADER;
#define DNS_HEADER_SIZE sizeof(DNS_HEADER)

// ��ѯ����
#define DNS_QUERY_TYPE_A		1	// ��ѯIPv4��ַ
#define DNS_QUERY_TYPE_NS		2	// ��ѯ����������
#define DNS_QUERY_TYPE_CNAME	5	// ��ѯ�淶����
#define DNS_QUERY_TYPE_SOA		6	// ��ѯ��Ȩ����Ŀ�ʼ
#define DNS_QUERY_TYPE_WKS		11	// ��ѯ��֪��������
#define DNS_QUERY_TYPE_PTR		12	// ��IP��ַת��������
#define DNS_QUERY_TYPE_HINFO	13	// ������Ϣ
#define DNS_QUERY_TYPE_MINFO	14	// ������ʼ��б���Ϣ
#define DNS_QUERY_TYPE_MX		15	// �ʼ�����
#define DNS_QUERY_TYPE_TXT		16	// �����ִ�
#define DNS_QUERY_TYPE_AAAA		28	// ���������IPv6��ַ
#define DNS_QUERY_TYPE_AXFR		252	// ����������������
#define DNS_QUERY_TYPE_ANY		255	// �����м�¼������
// ��ѯЭ����
#define DNS_QUERY_CLASS_IN	1	// ������
#define DNS_QUERY_CLASS_CH	3	// CHAOS��
#define DNS_QUERY_CLASS_HS	4	// Hesiod [Dyer 87]
#define DNS_QUERY_CLASS_ANY	255	// ������
// DNS��ѯ����
typedef struct _vDNS_QUESTION
{
	WORD Type;		// ��ѯ����
	WORD Class;		// ��ѯЭ����
}DNS_QUESTION, *PDNS_QUESTION;
#define DNS_QUESTION_SIZE sizeof(DNS_QUESTION)

// ��Դ��¼��ʽ
typedef struct _vDNS_RESOURCE_RECORD
{
	WORD Type;		// ��ѯ����
	WORD Class;		// ��ѯЭ����
	DWORD TTL;		// ����ʱ��
	WORD DataLength;	// ���ݳ���
	BYTE Data[0];	// ����
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