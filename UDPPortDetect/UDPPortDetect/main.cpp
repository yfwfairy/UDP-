#define WIN32_LEAN_AND_MEAN	
#include<iostream>
#include<WinSock2.h>
#include<string>
#pragma comment (lib,"ws2_32.lib")	//加载ws2_32库文件

using namespace std;
const int MAX_BUFLENGTH = 8000;
//ICMP类型字段，此次扫描实验收到的都是ICMP_PORT_UNREACHABLE
const BYTE ICMP_PORT_UNREACHABLE_PORT = 3; //端口不可达type
const BYTE ICMP_UNREACHABLE = 3;           //端口不可达code
const BYTE ICMP_HOST_UNREACH = 1;          //主机不可达code

//IP报头，用来提取ICMP报文中IP头中的sourceIP
typedef struct
{
	unsigned char hdr_len : 4;         //4位头部长度
	unsigned char version : 4;         //4位版本号
	unsigned char tos;               //8位服务类型
	unsigned short total_len;        //16位总长度
	unsigned short identifier;       //16位标识符
	unsigned short frag_and_flags;   //3位标志加13位片偏移
	unsigned char ttl;               //8位生存时间
	unsigned char protocol;          //8位上层协议号
	unsigned short checksum;         //16位效验和
	unsigned long sourceIP;          //32位源IP地址
	unsigned long destIP;            //32位目的IP地址
}IP_HEADER;

//ICMP报头
typedef struct
{
	BYTE type;     //8位类型字段
	BYTE code;     //8位代码字段
	USHORT cksum;  //16位效验和
	USHORT id;     //16位标识符
	USHORT seq;    //16位序列号
}ICMP_HEADER;


//报文解码结构
typedef struct
{
	UINT port;               //返回报文的端口号
	in_addr dwIPaddr;        //返回报文的IP地址
	BYTE code;
	BYTE type;
}DECODE_RESULT;

//对数据包进行解码,判断是否是unreachable的ICMP报文，提取出ip和port
BOOL DecodeIcmpResponse(char *pBuf, int iPacketSize, DECODE_RESULT &decodeResult)
{
	//检查数据报大小的合法性，其实没必要前面已经判断过总长度需要为56
	IP_HEADER *pIpHdr = (IP_HEADER*)pBuf;
	int iIpHdrLen = pIpHdr->hdr_len * 4;
	if (iPacketSize < (int)(iIpHdrLen + sizeof(ICMP_HEADER)))
	{
		cout << "error packSize too short" << endl;
		return FALSE;
	}
		
	//根据ICMP报文类型提取ID字段和序列号字段
	ICMP_HEADER *pIcmpHdr = (ICMP_HEADER*)(pBuf + iIpHdrLen);
	UINT port;
	struct icmp* icmp = (struct icmp*)(pBuf + iIpHdrLen);
	//cout << "type:" << pIcmpHdr->type + 0 << " code: " <<pIcmpHdr->code  + 0<< endl;
	port = (UINT)ntohs(*(u_short*)(pBuf + 20 + 8 + 20 + 2));
	decodeResult.code = pIcmpHdr->code;
	decodeResult.type = pIcmpHdr->type;
	decodeResult.port = port;
	decodeResult.dwIPaddr.S_un.S_addr = pIpHdr->sourceIP;
	if (pIcmpHdr->code == ICMP_UNREACHABLE && pIcmpHdr->type == ICMP_PORT_UNREACHABLE_PORT)    //ICMP端口不可达报文
	{
		//cout << "port:" << port << " sourceID:" << pIpHdr->sourceIP <<endl;
		return true;
	}
	else {
		return false;
	}
}

//获取host列表中最后一个ip，但不知道是否是可以ping到对端的ip，仅用作没有传入sourceIp参数时备用。
BOOLEAN getLocalIp(in_addr& addr)
{
	char szText[256];
	//获取本机主机名称
	int iRet;
	iRet = gethostname(szText, 256);
	int a = WSAGetLastError();
	if (iRet != 0)
	{
		printf("gethostname()  Failed!");
		return -1;
	}
	//通过主机名获取到地址信息
	HOSTENT *host = gethostbyname(szText);
	if (NULL == host)
	{
		printf("gethostbyname() Failed!");
		return false;
	}
	for (int i = 0;; i++)
	{
		char *p = host->h_addr_list[i];
		if (NULL == p)
		{
			break;
		}
		memcpy(&(addr.S_un.S_addr), p, host->h_length);
		char*szIP = ::inet_ntoa(addr);
		printf("本机的ip地址是：%s\n", szIP);
	}
}

//scanUDPPort(string,string,int,int,int) : 扫描UDP端口, sourceIp: 本地IP地址(一般是局域网IP)，targetIp:对端IP地址，startPort:起始端口号, endPort:结束端口号, retrans:没有收到ICMP包时重传次数
void scanUDPPort(string sourceIp,string targetIp, const int startPort, const int endPort, const int retrans) {
	WSADATA wsaData;
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	int currentPort;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		cout << "socket init error!";
		return;
	}
	SOCKET sendSocket = socket(AF_INET,SOCK_DGRAM, 0);
	if (sendSocket == INVALID_SOCKET) {
		cout << "sendSocket create error";
		return;
	}
	SOCKET recvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (recvSocket == INVALID_SOCKET) {
		cout << "recvSocket create error";
		return;
	}

	server.sin_family = AF_INET;

	//连接ICMP套接字到可以ping通对端的IP
	if (sourceIp.empty()) {
		getLocalIp(server.sin_addr);
	}
	else {
		server.sin_addr.s_addr = inet_addr(sourceIp.c_str());
	}
	//先为ICMP套接字随便绑定一个端口
	server.sin_port = htons(0);

	//连接ICMP套接字到本地Wifi的IP，不知道为啥。。。
	bind(recvSocket, (sockaddr*)&server, sizeof(server));

	// 设置套接字接收所有数据包(混杂模式)
	DWORD uiOptval = 1;
	char charRecv[10];
	DWORD dwBytesRet = 0;
	WSAIoctl(recvSocket, (IOC_IN | IOC_VENDOR | 1), &uiOptval, sizeof(uiOptval), charRecv, sizeof(charRecv), &dwBytesRet, NULL, NULL);
	
	fd_set fd;
	DECODE_RESULT decodeResult;      //传递给报文解码函数的结构化参数
	char buff[MAX_BUFLENGTH];
	int currentRetrans = 0;
	bool needRetrans = false;
	//scan
	for (currentPort = startPort; currentPort <= endPort; currentPort++) {
		server.sin_port = htons(currentPort); 
		server.sin_addr.s_addr = inet_addr(targetIp.data());
		ret = sendto(sendSocket, NULL, 0, 0, (sockaddr*)&server, sizeof(server));
		if (ret == SOCKET_ERROR) {
			cout << "send to port: " << currentPort << " error" << endl;
			continue;
		}
		timeval tv = { 1,0 }; //设置超时等待时间

		while (true) {
			FD_ZERO(&fd);
			FD_SET(recvSocket, &fd);
			int res = select(0, &fd, NULL, NULL, &tv);
			if (res > 0) {
				struct ip *ip;
				struct icmp *icmp;
				int hlen;
				UINT port;
				memset(&ip, 0, sizeof(ip));
				int length = recvfrom(recvSocket, buff, MAX_BUFLENGTH, 0, NULL, NULL);
				if (length != 56) {
					cout << "recvfrom length:" << length << endl;
					continue;
				}
				if (DecodeIcmpResponse(buff, length, decodeResult)) {
					if (decodeResult.dwIPaddr.s_addr == server.sin_addr.s_addr && decodeResult.port == currentPort) {
						//cout << "recv icmp from addr:" << inet_ntoa(decodeResult.dwIPaddr) << " port:" << currentPort << endl;
						break;
					}
					else {
						cout << "not compared icmp from addr:" << inet_ntoa(decodeResult.dwIPaddr) << " port:" << currentPort << endl;
						continue;
					}
				}
				else {
					BYTE code = decodeResult.code;
					if (code == ICMP_HOST_UNREACH) {
						cout << "主机不可达，停止扫描(stop)" << endl;
						//TODO:
						//主机不可访问，停止扫描
					}
					continue;
				}
			}
			else {
				needRetrans = true;
			}
			break;
		}
		if (needRetrans) {
			if (currentRetrans < retrans) {
				currentRetrans++;
				currentPort--;
			}
			else {
				currentRetrans = 0;
				//TODO:
				//此处为没有收到ICMP包的UDP端口，表示可以扫描到。端口号为currentPort。
				//可以在此函数中加入回调函数，更新界面UI。
				cout << "scan success ipAddress:" << inet_ntoa(server.sin_addr) << " port:" << currentPort << endl;
			}
			needRetrans = false;
		}
		else {
			currentRetrans = 0;
		}
	}
	closesocket(sendSocket);
	closesocket(recvSocket);
	WSACleanup();
}

int main() {
	scanUDPPort("192.168.1.5","192.168.1.4",53300, 65535,5);
}


