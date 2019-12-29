#include "stdafx.h"
#include "CDnsLookup.h"

CDnsLookup::CDnsLookup()
{
}

CDnsLookup::~CDnsLookup()
{
}

BOOL CDnsLookup::Lookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList)
{
	BOOL Result = FALSE;

	Result = this->UdpLookup(DnsServerIP, DomainName, ResultIpList);
	if (!Result)
	{
		Result = this->TcpLookup(DnsServerIP, DomainName, ResultIpList);
	}

	return Result;
}

BOOL CDnsLookup::UdpLookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList)
{
	BOOL Result = FALSE;
	SOCKET Socket = NULL;
	SOCKADDR_IN Addr = { 0 };
	PDNS_HEADER DnsHeader = NULL;
	WORD RequestDataSize = 0;
	PDNS_HEADER ResponseHeader = NULL;
	DWORD ResponseSize = 0;
	DWORD ReadSize = 0;
	BOOL bDontLinger = FALSE;

	do 
	{
		if (DnsServerIP == NULL ||
			DomainName == NULL)
		{
			break;
		}

		Socket = socket(AF_INET, SOCK_DGRAM, 0);
		if (Socket == NULL || Socket == INVALID_SOCKET)
		{
			break;
		}

		setsockopt(Socket, SOL_SOCKET, SO_DONTLINGER, (const char*)&bDontLinger, sizeof(bDontLinger));
		setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&s_Timeout, sizeof(s_Timeout));
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&s_Timeout, sizeof(s_Timeout));

		Addr.sin_addr.S_un.S_addr = inet_addr(DnsServerIP);
		Addr.sin_family = AF_INET;
		Addr.sin_port = htons(DNS_PORT);

		// 生成查询数据
		DnsHeader = this->GenerateRequestData(DomainName, &RequestDataSize);
		if (DnsHeader == NULL)
		{
			break;
		}

		// 发送查询数据
		if (!this->UdpSend(Socket, Addr, DnsHeader, RequestDataSize))
		{
			break;
		}
		// 接收查询结果
		// 接收头部数据
		ResponseSize = 512;
		ResponseHeader = (PDNS_HEADER)malloc(ResponseSize);
		if (ResponseHeader == NULL)
		{
			break;
		}
		ZeroMemory(ResponseHeader, ResponseSize);

		if (!this->UdpRecv(Socket, Addr, ResponseHeader, &ResponseSize))
		{
			break;
		}
		if (ResponseSize < DNS_HEADER_SIZE)
		{
			break;
		}

		if (!this->AnalyzeData(ResponseHeader, ResultIpList))
		{
			break;
		}

		Result = TRUE;
	} while (FALSE);

	if (Socket)
	{
		closesocket(Socket);
	}
	if (DnsHeader)
	{
		free(DnsHeader);
	}

	return Result;
}

BOOL CDnsLookup::TcpLookup(LPCSTR DnsServerIP, LPCSTR DomainName, std::map<std::string, std::string>& ResultIpList)
{
	BOOL Result = FALSE;
	SOCKET Socket = NULL;
	SOCKADDR_IN Addr = { 0 };
	PDNS_HEADER DnsHeader = NULL;
	WORD RequestDataSize = 0;
	PDNS_HEADER ResponseHeader = NULL;
	WORD ResponseDataSize = 0;
	DWORD RecvSize = 0;
	DWORD ReadSize = 0;
	BOOL bDontLinger = FALSE;

	do
	{
		if (DnsServerIP == NULL ||
			DomainName == NULL)
		{
			break;
		}

		Socket = socket(AF_INET, SOCK_STREAM, 0);
		if (Socket == NULL || Socket == INVALID_SOCKET)
		{
			printf("socket: %d\n", WSAGetLastError());
			break;
		}

		setsockopt(Socket, SOL_SOCKET, SO_DONTLINGER, (const char*)&bDontLinger, sizeof(bDontLinger));
		setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&s_Timeout, sizeof(s_Timeout));
		setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&s_Timeout, sizeof(s_Timeout));

		Addr.sin_addr.S_un.S_addr = inet_addr(DnsServerIP);
		Addr.sin_family = AF_INET;
		Addr.sin_port = htons(DNS_PORT);

		if (connect(Socket, (sockaddr*)&Addr, sizeof(Addr)))
		{
			printf("connect: %d\n", WSAGetLastError());
			break;
		}

		// 生成查询数据
		DnsHeader = this->GenerateRequestData(DomainName, &RequestDataSize);
		if (DnsHeader == NULL)
		{
			break;
		}

		// 发送查询数据大小
		RequestDataSize = htons(RequestDataSize);
		if (!this->TcpSend(Socket, &RequestDataSize, sizeof(WORD)))
		{
			break;
		}
		// 发送查询数据
		RequestDataSize = ntohs(RequestDataSize);
		if (!this->TcpSend(Socket, DnsHeader, RequestDataSize))
		{
			break;
		}
		// 接收查询结果
		RecvSize = sizeof(ResponseDataSize);
		if (!this->TcpRecv(Socket, &ResponseDataSize, &RecvSize))
		{
			break;
		}
		// 接收头部数据
		RecvSize = ntohs(ResponseDataSize);
		ResponseHeader = (PDNS_HEADER)malloc(RecvSize);
		if (ResponseHeader == NULL)
		{
			break;
		}
		ZeroMemory(ResponseHeader, RecvSize);
		if (!this->TcpRecv(Socket, ResponseHeader, &RecvSize))
		{
			break;
		}
		if (RecvSize < DNS_HEADER_SIZE)
		{
			break;
		}

		if (!this->AnalyzeData(ResponseHeader, ResultIpList))
		{
			printf("AnalyzeData\n");
			break;
		}

		Result = TRUE;
	} while (FALSE);

	if (Socket)
	{
		closesocket(Socket);
	}
	if (DnsHeader)
	{
		free(DnsHeader);
	}

	return Result;
}

BOOL CDnsLookup::UdpSend(SOCKET Socket, SOCKADDR_IN Addr, PVOID SendBase, DWORD SendSize)
{
	BOOL Result = FALSE;
	int SockRet = SOCKET_ERROR;

	do
	{
		if (Socket == NULL ||
			Socket == INVALID_SOCKET)
		{
			break;
		}

		SockRet = sendto(Socket, (const char*)SendBase, SendSize, 0, (sockaddr*)&Addr, sizeof(Addr));
		if (SockRet == SOCKET_ERROR ||
			SockRet != SendSize)
		{
			break;
		}

		Result = TRUE;
	} while (FALSE);

	return Result;
}

BOOL CDnsLookup::UdpRecv(SOCKET Socket, SOCKADDR_IN Addr, PVOID RecvBase, PDWORD RecvSize)
{
	BOOL Result = FALSE;
	int SockRet = SOCKET_ERROR;
	int FromLen = 0;

	do
	{
		if (Socket == NULL ||
			Socket == INVALID_SOCKET ||
			RecvBase == NULL ||
			RecvSize == NULL ||
			*RecvSize == 0)
		{
			break;
		}

		FromLen = sizeof(Addr);
		SockRet = recvfrom(Socket, (char*)RecvBase, *RecvSize, 0, (sockaddr*)&Addr, &FromLen);
		if (SockRet <= 0)
		{
			break;
		}
		*RecvSize = SockRet;

		Result = TRUE;
	} while (FALSE);

	return Result;
}

BOOL CDnsLookup::TcpSend(SOCKET Socket, PVOID SendBase, DWORD SendSize)
{
	BOOL Result = FALSE;
	int SockRet = SOCKET_ERROR;

	do 
	{
		if (Socket == NULL ||
			Socket == INVALID_SOCKET)
		{
			break;
		}

		SockRet = send(Socket, (const char*)SendBase, SendSize, 0);
		if (SockRet == SOCKET_ERROR ||
			SockRet != SendSize)
		{
			break;
		}

		Result = TRUE;

	} while (FALSE);

	return Result;
}

BOOL CDnsLookup::TcpRecv(SOCKET Socket, PVOID RecvBase, PDWORD RecvSize)
{
	BOOL Result = FALSE;
	int SockRet = SOCKET_ERROR;
	DWORD RecvLen = 0;

	do
	{
		if (Socket == NULL ||
			Socket == INVALID_SOCKET ||
			RecvBase == NULL ||
			RecvSize == NULL ||
			*RecvSize == 0)
		{
			break;
		}

		while (TRUE)
		{
			SockRet = recv(Socket, (char*)RecvBase + RecvLen, *RecvSize - RecvLen, 0);
			if (SockRet <= 0)
			{
				break;
			}
			RecvLen += SockRet;
		}

		*RecvSize = RecvLen;
		Result = TRUE;
	} while (FALSE);

	return Result;
}

PDNS_HEADER CDnsLookup::GenerateRequestData(LPCSTR DomainName, PWORD DataSize)
{
	PDNS_HEADER DnsData = NULL;
	PDNS_QUESTION DnsQuestion = NULL;
	DWORD NameSize = 0;
	DWORD PacketSize = 0;
	std::vector<std::string> NameLabels;
	DWORD WriteLabelSize = 0;

	do 
	{
		if (DomainName == NULL ||
			DataSize == NULL)
		{
			break;
		}

		NameLabels = this->Split(DomainName, ".");
		if (NameLabels.empty())
		{
			break;
		}

		NameSize = strlen(DomainName) + 2;
		PacketSize = DNS_HEADER_SIZE + NameSize + DNS_QUESTION_SIZE;

		DnsData = (PDNS_HEADER)malloc(PacketSize);
		if (DnsData == NULL)
		{
			break;
		}
		ZeroMemory(DnsData, PacketSize);

		DnsData->TransactionID = (WORD)GetCurrentProcessId();

		DnsData->Flags.QR = DNS_FLAGS_QR_REQUEST;
		DnsData->Flags.opcode = DNS_FLAGS_OPCODE_QUERY;
		DnsData->Flags.AA = 0;
		DnsData->Flags.TC = 0;
		DnsData->Flags.RD = 1;
		DnsData->Flags.RA = 0;
		DnsData->Flags.zero = 0;
		DnsData->Flags.rcode = 0;

		*(PWORD)&DnsData->Flags = htons(*(PWORD)&DnsData->Flags);

		DnsData->Questions = htons(1);
		DnsData->AnswerRRs = 0;
		DnsData->AuthorityRRs = 0;
		DnsData->AdditionalRRs = 0;

		for (auto Label : NameLabels)
		{
			DnsData->Content[WriteLabelSize] = (BYTE)Label.length();
			memcpy(&DnsData->Content[WriteLabelSize + 1], Label.c_str(), Label.length());

			WriteLabelSize += Label.length() + 1;
		}
		DnsData->Content[WriteLabelSize] = 0;

		DnsQuestion = (PDNS_QUESTION)&DnsData->Content[WriteLabelSize + 1];
		DnsQuestion->Type = htons(DNS_QUERY_TYPE_A);
		DnsQuestion->Class = htons(DNS_QUERY_CLASS_IN);

		*DataSize = PacketSize;

	} while (FALSE);

	return DnsData;
}

std::vector<std::string> CDnsLookup::Split(std::string SourceStr, std::string SplitStr)
{
	std::vector<std::string> Result;
	int StartPos = 0;
	int EndPos = -1;

	do
	{
		EndPos = SourceStr.find(SplitStr, StartPos);
		if (EndPos == -1)
		{
			Result.push_back(SourceStr.substr(StartPos));
			break;
		}

		Result.push_back(SourceStr.substr(StartPos, EndPos - StartPos));
		StartPos = EndPos + SplitStr.length();
	} while (StartPos != -1);

	return Result;
}

DWORD CDnsLookup::DecodeDomainName(PDNS_HEADER DnsHeader, DWORD OffsetRead, std::string& DomainName)
{
	DWORD Result = 0;
	BOOL IsOffset = FALSE;

	if (DnsHeader)
	{
		while (TRUE)
		{
			BYTE Len = 0;

			Len = DnsHeader->Content[OffsetRead + Result];
			if (Len == 0)
			{
				break;
			}

			if (Len & 0xC0)
			{
				WORD JmpPos = ntohs(*(PWORD)&DnsHeader->Content[OffsetRead + Result]) & 0x3FFF;
				OffsetRead = JmpPos - DNS_HEADER_SIZE;

				this->DecodeDomainName(DnsHeader, OffsetRead, DomainName);

				IsOffset = TRUE;
				Result += 2;
				break;
			}

			if (!DomainName.empty())
			{
				DomainName += ".";
			}

			DomainName.append((char*)&DnsHeader->Content[OffsetRead + Result + 1], Len);
			Result += Len + 1;
		}

		if (Result > 0 && !IsOffset)
		{
			Result += 1;
		}
	}

	return Result;
}

BOOL CDnsLookup::AnalyzeData(PDNS_HEADER DnsHeader, std::map<std::string, std::string>& ResultIpList)
{
	BOOL Result = FALSE;
	DWORD ReadSize = 0;

	do 
	{
		if (DnsHeader == NULL)
		{
			break;
		}

		*(PWORD)&DnsHeader->Flags = ntohs(*(PWORD)&DnsHeader->Flags);
		DnsHeader->Questions = ntohs(DnsHeader->Questions);
		DnsHeader->AnswerRRs = ntohs(DnsHeader->AnswerRRs);
		DnsHeader->AuthorityRRs = ntohs(DnsHeader->AuthorityRRs);
		DnsHeader->AdditionalRRs = ntohs(DnsHeader->AdditionalRRs);

		if (DnsHeader->TransactionID != (WORD)GetCurrentProcessId() ||
			DnsHeader->Flags.QR != DNS_FLAGS_QR_RESPONSE ||
			DnsHeader->Flags.rcode != DNS_FLAGS_RCODE_NOERROR ||
			DnsHeader->Flags.opcode != DNS_FLAGS_OPCODE_QUERY ||
			DnsHeader->Questions != 1 ||
			DnsHeader->AnswerRRs == 0)
		{
			break;
		}

		for (int i = 0; i < DnsHeader->Questions; i++)
		{
			std::string DecodeNameStr;
			ReadSize += this->DecodeDomainName(DnsHeader, ReadSize, DecodeNameStr);
			ReadSize += DNS_QUESTION_SIZE;
		}

		// 接收资源数据
		for (int i = 0; i < DnsHeader->AnswerRRs; i++)
		{
			std::string DecodeNameStr;
			ReadSize += this->DecodeDomainName(DnsHeader, ReadSize, DecodeNameStr);
			PDNS_RESOURCE_RECORD DnsResourceRecord = (PDNS_RESOURCE_RECORD)&DnsHeader->Content[ReadSize];

			DnsResourceRecord->Type = ntohs(DnsResourceRecord->Type);
			DnsResourceRecord->Class = ntohs(DnsResourceRecord->Class);
			DnsResourceRecord->TTL = ntohl(DnsResourceRecord->TTL);
			DnsResourceRecord->DataLength = ntohs(DnsResourceRecord->DataLength);

			int iiii = DNS_RESOURCE_RECORD_SIZE;
			ReadSize += DNS_RESOURCE_RECORD_SIZE;

			if (DnsResourceRecord->Type == DNS_QUERY_TYPE_A &&
				DnsResourceRecord->Class == DNS_QUERY_CLASS_IN &&
				DnsResourceRecord->DataLength == 4)
			{
				CHAR IpStr[32] = { 0 };
				sprintf(IpStr, "%d.%d.%d.%d", DnsResourceRecord->Data[0], DnsResourceRecord->Data[1], DnsResourceRecord->Data[2], DnsResourceRecord->Data[3]);
				ResultIpList.insert(std::make_pair(IpStr, DecodeNameStr));

				ReadSize += DnsResourceRecord->DataLength;
			}
			else if (DnsResourceRecord->Type == DNS_QUERY_TYPE_CNAME &&
				DnsResourceRecord->Class == DNS_QUERY_CLASS_IN)
			{
				DecodeNameStr.clear();
				ReadSize += this->DecodeDomainName(DnsHeader, ReadSize, DecodeNameStr);
			}


		}

		if (!ReadSize)
		{
			ResultIpList.clear();
			break;
		}

		Result = TRUE;
	} while (FALSE);

	return Result;
}
