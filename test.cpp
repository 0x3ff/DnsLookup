#include "stdafx.h"
#include "CDnsLookup.h"

int main(int argc, char** argv)
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == SOCKET_ERROR)
	{
		return 0;
	}

	std::map<std::string, std::string> iplist;

	CDnsLookup DnsLookup;
	DnsLookup.Lookup("114.114.114.114", "www.baidu.com", iplist);

	for (auto i : iplist)
	{
		printf("%s ---> %s\n", i.first.c_str(), i.second.c_str());
	}

	WSACleanup();
	system("pause");
	return 0;
}