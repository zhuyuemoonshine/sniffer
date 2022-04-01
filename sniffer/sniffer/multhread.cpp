#include "multhread.h"
#include <QDebug>

multhread::multhread()
{
	this->isDone = true;
}

bool multhread::setPointer(pcap_t* pointer)
{
	this->pointer = pointer;
	if (pointer)
		return true;
	else
		return false;
}

void multhread::setFlag()
{
	this->isDone = false;
}

void multhread::resetFlag()
{
	this->isDone = true;
}

int multhread::ethernetPackageHandle(const u_char* pkt_content, QString& info)
{
	ETHER_HEADER* ethernet;
	u_short content_type;
	ethernet = (ETHER_HEADER*)(pkt_content);
	content_type = NTOHS(ethernet->_ether_type);
	switch (content_type)
	{
	case 0x0800://ip
	{
		int ipPackage = 0;
		int res = ipPackageHandle(pkt_content, ipPackage);
		switch (res)
		{
		case 1:
		{//icmp
			return icmpPackageHandle(pkt_content, info);
		}
		case 6:
		{//tcp
			return tcpPackageHandle(pkt_content, info, ipPackage);
		}
		case 17:
		{//udp
			return udpPackageHandle(pkt_content, info);
		}
		default:break;
		}
		return 0;
	}
	case 0x0806://arp
	{
		info = arpPackageHandle(pkt_content);
		return 1;
	}
	default:break;
	}
	return 0;
}

int multhread::ipPackageHandle(const u_char* pkt_content, int& ipPackage)
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->_protocol;
	char len = ip->_version_headerLen & 0x0f;
	ipPackage = NTOHS(ip->_totalLen) - len * 4;
	return protocol;
}

int multhread::tcpPackageHandle(const u_char* pkt_content, QString& info, int ipPackage) 
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 34);
	u_short src = NTOHS(tcp->_sport);
	u_short des = NTOHS(tcp->_dport);
	QString proSend = "";
	QString proRecv = "";

	int type = 3;

	//获取tcp载荷长度
	int delta = (tcp->_off_res_flag >> 12) * 4;
	int tcpLoader = ipPackage - delta;

	//提取源端口，目的端口
	if (src == 443 || des == 443)
	{
		if (src == 443)
			proSend = "(https)";
		else
			proRecv = "(https)";
	}
	info += QString::number(src) + proSend + "->" + QString::number(des) + proRecv;

	//提取标志位信息
	QString flag = "";
	if (tcp->_off_res_flag & 0x20) flag += "URG,";
	if (tcp->_off_res_flag & 0x10) flag += "ACK,";
	if (tcp->_off_res_flag & 0x08) flag += "PSH,";
	if (tcp->_off_res_flag & 0x04) flag += "RST,";
	if (tcp->_off_res_flag & 0x02) flag += "SYN,";
	if (tcp->_off_res_flag & 0x01) flag += "FIN,";
	if (flag != "")
	{
		flag = flag.left(flag.length() - 1);
		info += "[" + flag + "]";
	}

	//提取窗口大小，序列号
	u_int sequence = NTOHSL(tcp->_seqNum);
	u_int ack = NTOHSL(tcp->_ackNum);
	u_short window = NTOHS(tcp->_winSize);
	info += "Seq=" + QString::number(sequence) + "Ack=" + QString::number(ack) + "WindowSize=" + QString::number(window)+"len="+QString::number(tcpLoader);

	return type;
}

int multhread::udpPackageHandle(const u_char* pkt_content, QString& info)
{
	UDP_HEADER* udp;
	udp = (UDP_HEADER*)(pkt_content + 34);
	u_short des = NTOHS(udp->_dport);
	u_short src = NTOHS(udp->_sport);
	if (des == 53 || src == 53)
	{
		info = dnsPackageHandle(pkt_content);
		return 5;
	}
	else 
	{
		QString res = QString::number(src) + "->" + QString::number(des);
		u_short data_len = NTOHS(udp->_len);
		res += "len=" + QString::number(data_len);
		info += res;
		return 4;
	}
}

int multhread::icmpPackageHandle(const u_char* pkt_content, QString& info)
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_char type = icmp->_type;
	u_char code = icmp->_code;
	if (code == 0)
	{
		if (type == 8)
		{
			info += "Echo (ping) request  ";
		}
		else if (type == 0)
		{
			info += "Echo (ping) reply  ";
		}
		else if (type == 3)
		{
			info += "Networt unreachable  ";
		}
	}
	u_short id = NTOHS(icmp->_identification);
	char buf[1024];
	_itoa_s(id, buf, 16);
	QString sId = buf;
	info += "id=0x" + sId + ",  ";
	u_short seq = NTOHS(icmp->_seq);
	info += "seq=" + QString::number(seq);
	return 2;
}

QString multhread::dnsPackageHandle(const u_char* pkt_content)
{
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	u_short id=NTOHS(dns->_id);
	u_short type = NTOHS(dns->_flag);
	QString info = "";
	if ((type & 0xf800) == 0x0000)
	{
		info = "Standard query ";
	}
	else if ((type & 0xf800) == 0x8000)
	{
		info = "Standard query response ";
	}
	QString name = "";
	char* domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
	while (*domain != 0x00)
	{
		if (domain && (*domain) <= 64)
		{
			int length = *domain;
			domain++;
			for (int i = 0; i < length; i++)
			{
				name += (*domain);
				domain++;
			}
			name += ".";
		}
		else
			break;
	}
	if (name != "")
	{
		name = name.left(name.length() - 1);
	}
	return info + "0x" + QString::number(id, 16) + " " + name;
}

QString multhread::arpPackageHandle(const u_char* pkt_content)
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);

	u_short op = NTOHS(arp->_op_type);
	QString res = "";
	u_char* dipaddr = arp->_des_ip_addr;
	QString desIp = QString::number(*dipaddr) + "."
		+ QString::number(*(dipaddr + 1)) + "."
		+ QString::number(*(dipaddr + 2)) + "."
		+ QString::number(*(dipaddr + 3));
	u_char* sipaddr = arp->_src_ip_addr;
	QString srcIp= QString::number(*sipaddr) + "."
		+ QString::number(*(sipaddr + 1)) + "."
		+ QString::number(*(sipaddr + 2)) + "."
		+ QString::number(*(sipaddr + 3));

	u_char* src_eth_addr = arp->_src_ether_addr;
	QString srcEth = byteToString(src_eth_addr, 1) + ":"
		+ byteToString(src_eth_addr + 1, 1) + ":"
		+ byteToString(src_eth_addr + 2, 1) + ":"
		+ byteToString(src_eth_addr + 3, 1) + ":"
		+ byteToString(src_eth_addr + 4, 1) + ":"
		+ byteToString(src_eth_addr + 5, 1);

	if (op == 1)
	{
		res = "who has " + desIp + "? Tell " + srcIp;
	}
	else if (op == 2)
	{
		res = srcIp + " is at " + srcEth;
	}
	return res;
}

QString multhread::byteToString(u_char* str, int size)
{
	QString res = "";
	for (int i = 0; i < size; i++)
	{
		char one = str[i] >> 4;
		if (one >= 0x0A)
			one += 0x41 - 0x0A;
		else one += 0x30;
		char two = str[i] & 0xF;
		if (two >= 0x0A)
			two += 0x41 - 0x0A;
		else two += 0x30;
		res.append(one);
		res.append(two);
	};
	return res;
}

void multhread::run()
{
	while (1)
	{
		if (isDone)
			break;
		else
		{
			int ret = pcap_next_ex(pointer, &(packHeader), &(packData));
			if (ret != 1) continue;  // 捕获失败，循环继续
			local_time_sec = packHeader->ts.tv_sec;
			localtime_s(&local_time, &local_time_sec);
			strftime(timeString, sizeof(timeString), "%H:%M:%S", &local_time);
			QString info = "";
			int type = ethernetPackageHandle(packData, info);
			if (type)
			{
				DataPackage data;
				int len = packHeader->len;
				data.setDataLength(len);
				data.setInfo(info);
				data.setTimeStmp(timeString);
				data.setPackageType(type);
				data.setPointer(packData, len);
				emit send(data);
			}
		}
	}
}