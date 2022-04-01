#include "DataPackage.h"
#include <QMetaType>

DataPackage::DataPackage()
{
	qRegisterMetaType<DataPackage>("DataPackage");
	this->timeStmp = "";
	this->data_length = 0;
	this->package_type = 0;
	this->pkt_content = nullptr;
}

void DataPackage::setDataLength(u_int data_length)
{
	this->data_length = data_length;
}

void DataPackage::setTimeStmp(QString timeStmp)
{
	this->timeStmp = timeStmp;
}

void DataPackage::setInfo(QString info)
{
	this->info = info;
}

void DataPackage::setPackageType(int type)
{
	this->package_type = type;
}

void DataPackage::setPointer(const u_char* pkt_content,int size)
{
	this->pkt_content = (u_char*)malloc(size);
	if (this->pkt_content != nullptr)
		memcpy((char*)(this->pkt_content), pkt_content, size);
	else this->pkt_content = nullptr;
}

QString DataPackage::getDataLength()
{
	return QString::number(this->data_length);
}

QString DataPackage::getTimeStmp()
{
	return this->timeStmp;
}

QString DataPackage::getInfo()
{
	return this->info;
}

QString DataPackage::getPackageType()
{
	switch (this->package_type)
	{
	case 1:	return "ARP";
	case 2:	return "ICMP";
	case 3:	return "TCP";
	case 4:	return "UDP";
	case 5:	return "DNS";
	case 6:	return "TLS";
	case 7:	return "SSL";
	default:return "";
	}
}

u_int DataPackage::getDataLengthInt()
{
	return this->data_length;
}

int DataPackage::getPackageTypeInt()
{
	return this->package_type;
}


QString DataPackage::getDesMacAddr()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)pkt_content;
	u_char* addr = eth->_ether_dhost;
	if (addr)
	{
		QString res = byteToString(addr, 1) + ":"
			+ byteToString(addr + 1, 1) + ":"
			+ byteToString(addr + 2, 1) + ":"
			+ byteToString(addr + 3, 1) + ":"
			+ byteToString(addr + 4, 1) + ":"
			+ byteToString(addr + 5, 1);
		if (res == "FF:FF:FF:FF:FF:FF")return "FF:FF:FF:FF:FF:FF(Broadcast)";
		else return res;
	}
}

QString DataPackage::getSrcMacAddr()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)pkt_content;
	u_char* addr = eth->_ether_shost;
	if (addr)
	{
		QString res = byteToString(addr, 1) + ":"
			+ byteToString(addr + 1, 1) + ":"
			+ byteToString(addr + 2, 1) + ":"
			+ byteToString(addr + 3, 1) + ":"
			+ byteToString(addr + 4, 1) + ":"
			+ byteToString(addr + 5, 1);
		if (res == "FF:FF:FF:FF:FF:FF")return "FF:FF:FF:FF:FF:FF(Broadcast)";
		else return res;
	}
}

QString DataPackage::getSrcIpAddr()
{
	/*
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	u_int addr = NTOHSL(ip->_src);
	if (addr)
	{
		QString res = iptos(addr);
		return res;
	}*/
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	sockaddr_in srcAddr;
	srcAddr.sin_addr.s_addr = ip->_src;
	return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPackage::getDesIpAddr() 
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	u_int addr = NTOHSL(ip->_desc);
	if (addr)
	{
		QString res = iptos(addr);
		return res;
	}
}

QString DataPackage::getSource()
{
	if (this->package_type == 1)
		return getSrcMacAddr();
	else return getSrcIpAddr();
}

QString DataPackage::getDestination()
{
	if (this->package_type == 1)
		return getDesMacAddr();
	else return getDesIpAddr();
}

QString DataPackage::getMacType()
{
	ETHER_HEADER* eth;
	eth = (ETHER_HEADER*)(pkt_content);
	u_short type = NTOHS(eth->_ether_type);
	if (type == 0x0800)
		return "IPv4(0x0800)";
	else if (type == 0x0806)
		return "ARP(0x0806)";
	else return "";
}


/******提取IP协议数据******/
QList<QTreeWidgetItem*> DataPackage::getIp()
{
	QString ipVersion = getIpVersion();
	QString ipHeaderLength = getIpHeaderLength();
	QString ipTotalLength = getIpTotalLength();
	QString ipProtocol = getIpProtocol();
	QString ipTTL = getIpTTL();
	QString srcIp = getSrcIpAddr();
	QString desIp = getDesIpAddr();
	QList<QTreeWidgetItem*> info;
	info.append(new QTreeWidgetItem(QStringList() << ipVersion));
	info.append(new QTreeWidgetItem(QStringList() << ipHeaderLength));
	info.append(new QTreeWidgetItem(QStringList() << ipTotalLength));
	info.append(new QTreeWidgetItem(QStringList() << ipTTL));
	info.append(new QTreeWidgetItem(QStringList() << "Protocol :" + ipProtocol));
	info.append(new QTreeWidgetItem(QStringList() << "Source Address :" + srcIp));
	info.append(new QTreeWidgetItem(QStringList() << "Destination Address :" + desIp));
	return info;
}

QString DataPackage::getIpVersion()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->_protocol;
	char version = ip->_version_headerLen & 0xf0;
	if (version == 0x40);
	{
		return "Version:4";
	}
}

QString DataPackage::getIpHeaderLength()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->_protocol;
	char length = ip->_version_headerLen & 0x0f;
	QString res = "Header Length:" + QString::number(length * 4) + "bytes";
	return res;
}

QString DataPackage::getIpTotalLength()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	u_short totalLength = NTOHS(ip->_totalLen);
	return "Total Length:" + QString::number(totalLength);
}

QString DataPackage::getIpTTL()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	u_char  ttl = ip->_timeLive;
	return "Time to Live:" + QString::number(ttl);
}

QString DataPackage::getIpProtocol()
{
	IP_HEADER* ip;
	ip = (IP_HEADER*)(pkt_content + 14);
	int protocol = ip->_protocol;
	switch(protocol)
	{
	case 1:
	{//icmp
		return "ICMP(1)";
	}
	case 6:
	{//tcp
		return "TCP(6)";
	}
	case 17:
	{//udp
		return "UDP(17)";
	}
	default:break;
	}
	return 0;
}


/******提取ARP协议数据******/
QList<QTreeWidgetItem*> DataPackage::getArp()
{
	QList<QTreeWidgetItem*> info;
	QString hType = getArpHType();
	QString pType = getArpPType();
	QString sMacAddr = getArpSMacAddr();
	QString tMacAddr = getArpTMacAddr();
	QString sIpAddr = getArpSIpAddr();
	QString tIpAddr = getArpSIpAddr();
	QString Op = getArpOp();
	info.append(new QTreeWidgetItem(QStringList() << hType));
	info.append(new QTreeWidgetItem(QStringList() << pType));
	info.append(new QTreeWidgetItem(QStringList() << "Opcode: " + Op));
	info.append(new QTreeWidgetItem(QStringList() << sMacAddr));
	info.append(new QTreeWidgetItem(QStringList() << sIpAddr));
	info.append(new QTreeWidgetItem(QStringList() << tMacAddr));
	info.append(new QTreeWidgetItem(QStringList() << tIpAddr));
	return info;
}

QString DataPackage::getArpHType()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_short hType = NTOHS(arp->_type);
	QString res = "Hardware Type :";
	if (hType == 1)
	{
		res += "Ethernet(1)";
	}
	else
	{
		res += "(" + QString::number(hType) + ")";
	}
	return res;
}

QString DataPackage::getArpOp()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_short op = NTOHS(arp->_op_type);
	QString res = "";
	if (op == 1)
	{
		res = "request(1)";
	}
	else if (op == 2)
	{
		res = "reply(2)";
	}
	return res;
}

QString DataPackage::getArpPType()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_short protocol = NTOHS(arp->_protocol);
	if (protocol == 0x0800)
		return "Protocol Type: IPv4(0x0800)";
	else
		return "Protocol Type: " + QString::number(protocol);
}

QString DataPackage::getArpSMacAddr()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_char* addr = arp->_src_ether_addr;
	QString res = byteToString(addr, 1) + ":"
		+ byteToString(addr + 1, 1) + ":"
		+ byteToString(addr + 2, 1) + ":"
		+ byteToString(addr + 3, 1) + ":"
		+ byteToString(addr + 4, 1) + ":"
		+ byteToString(addr + 5, 1);
	return "Sender Mac Address: " + res;
}

QString DataPackage::getArpTMacAddr()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_char* addr = arp->_des_ether_addr;
	QString res = byteToString(addr, 1) + ":"
		+ byteToString(addr + 1, 1) + ":"
		+ byteToString(addr + 2, 1) + ":"
		+ byteToString(addr + 3, 1) + ":"
		+ byteToString(addr + 4, 1) + ":"
		+ byteToString(addr + 5, 1);
	return "Target Mac Address: " + res;
}

QString DataPackage::getArpSIpAddr()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_char* addr = arp->_src_ip_addr;
	QString res = QString::number(*addr) + "."
		+ QString::number(*(addr + 1)) + "."
		+ QString::number(*(addr + 2)) + "."
		+ QString::number(*(addr + 3));
	return "Sender Ip Address: " + res;
}

QString DataPackage::getArpTIpAddr()
{
	ARP_HEADER* arp;
	arp = (ARP_HEADER*)(pkt_content + 14);
	u_char* addr = arp->_des_ip_addr;
	QString res = QString::number(*addr) + "."
		+ QString::number(*(addr + 1)) + "."
		+ QString::number(*(addr + 2)) + "."
		+ QString::number(*(addr + 3));
	return "Target Ip Address: " + res;
}


/******提取TCP协议数据******/
QString DataPackage::getTcpSrcPort()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 34);
	u_short res = NTOHS(tcp->_sport);
	return QString::number(res);
}

QString DataPackage::getTcpDesPort()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 34);
	u_short res = NTOHS(tcp->_dport);
	return QString::number(res);
}

QString DataPackage::getTcpSeq()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 34);
	u_int res = NTOHSL(tcp->_seqNum);
	return "Sequence Number: " + QString::number(res);
}

QString DataPackage::getTcpAck()
{
	TCP_HEADER* tcp;
	tcp = (TCP_HEADER*)(pkt_content + 34);
	u_int res = NTOHSL(tcp->_ackNum);
	return "Acknowladge Number: " + QString::number(res);
}


/******提取UDP协议数据******/
QString DataPackage::getUdpSrcPort()
{
	UDP_HEADER* udp;
	udp = (UDP_HEADER*)(pkt_content + 34);
	u_short res = NTOHS(udp->_sport);
	return QString::number(res);
}

QString DataPackage::getUdpDesPort()
{
	UDP_HEADER* udp;
	udp = (UDP_HEADER*)(pkt_content + 34);
	u_short res = NTOHS(udp->_dport);
	return QString::number(res);
}

QString DataPackage::getUdpLength()
{
	UDP_HEADER* udp;
	udp = (UDP_HEADER*)(pkt_content + 34);
	u_short res = NTOHS(udp->_len);
	return QString::number(res);
}

QString DataPackage::iptos(u_int in)
{
	u_char* p;
	p = (u_char*)&in;
	QString res="";
	res = QString::number(*(p + 3)) + "."
		+ QString::number(*(p + 2)) + "."
		+ QString::number(*(p + 1)) + "."
		+ QString::number(*p);
	//memset(buf, 0x00, sizeof buf);
	//sprintf_s(buf, 512, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	return res;
}


/******提取ICMP协议数据******/
QList<QTreeWidgetItem*> DataPackage::getIcmp()
{
	QList<QTreeWidgetItem*> info;
	info.append(new QTreeWidgetItem(QStringList() << getIcmpType()));
	info.append(new QTreeWidgetItem(QStringList() << getIcmpCode()));
	info.append(new QTreeWidgetItem(QStringList() << getIcmpCheckSum()));
	info.append(new QTreeWidgetItem(QStringList() << getIcmpId()));
	info.append(new QTreeWidgetItem(QStringList() << getIcmpSeq()));
	return info;
}

QString DataPackage::getIcmpType()
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_char type = icmp->_type;
	u_char code = icmp->_code;
	if (code == 0)
	{
		if (type == 8)
		{
			return "Type: 8 (Echo (ping) request)";
		}
		else if (type == 0)
		{
			return "Type: 0 (Echo (ping) reply)";
		}
		else if (type == 11)
		{
			return "Type: 11 (Out of time)";
		}
	}
	else
	{
		return "Type: " + QString::number(type);
	}
}

QString DataPackage::getIcmpCode()
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_char code = icmp->_code;
	return "Code: " + QString::number(code);
}

QString DataPackage::getIcmpCheckSum()
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_short checkSum = NTOHS(icmp->_checkSum);
	char buf[1024];
	_itoa_s(checkSum, buf, 16);
	QString cs = buf;
	return "CheckSum: 0x" + cs;
}

QString DataPackage::getIcmpId()
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_short id = NTOHS(icmp->_identification);
	char buf[1024];
	_itoa_s(id, buf, 16);
	QString sid = buf;
	return "Identifier: 0x" + sid;
}

QString DataPackage::getIcmpSeq()
{
	ICMP_HEADER* icmp;
	icmp = (ICMP_HEADER*)(pkt_content + 34);
	u_short seq = NTOHS(icmp->_seq);
	return "Sequence Number: " + QString::number(seq);
}


/******提取DNS协议数据******/
QList<QTreeWidgetItem*> DataPackage::getDns()
{
	QList<QTreeWidgetItem*> info;
	info.append(new QTreeWidgetItem(QStringList() << getDnsId()));
	QString question = getDnsQuestionNumber();
	QString answer = getDnsAnswerNumber();
	QTreeWidgetItem* flag = new QTreeWidgetItem(QStringList() << "Flags:"+getDnsFlags());
	flag->addChildren(getDnsFlagInfo());
	info.append(flag);
	info.append(new QTreeWidgetItem(QStringList() << "Qusetions: " + getDnsQuestionNumber()));
	info.append(new QTreeWidgetItem(QStringList() << "Answer RRs: " + getDnsAnswerNumber()));
	info.append(new QTreeWidgetItem(QStringList() << "Authority RRS: "+getDnsAuthorityNumber()));
	info.append(new QTreeWidgetItem(QStringList() << "Additional RRS: " + getDnsAdditionalNumber()));
	int offset = 0;
	if (question == "1") {
		QString domainInfo;
		int Type;
		int Class;
		getDnsQueriesDomain(domainInfo, Type, Class);
		QTreeWidgetItem* queryDomainTree = new QTreeWidgetItem(QStringList() << "Queries");
		info.append(queryDomainTree);
		offset += (4 + domainInfo.size() + 2);
		QString type = getDnsDomainType(Type);
		QTreeWidgetItem* querySubTree = new QTreeWidgetItem(QStringList() << domainInfo + " type " + type + ", class IN");
		queryDomainTree->addChild(querySubTree);
		querySubTree->addChild(new QTreeWidgetItem(QStringList() << "Name:" + domainInfo));
		querySubTree->addChild(new QTreeWidgetItem(QStringList() << "[Name Length:" + QString::number(domainInfo.size()) + "]"));
		querySubTree->addChild(new QTreeWidgetItem(QStringList() << "Type:" + type + "(" + QString::number(Type) + ")"));
		querySubTree->addChild(new QTreeWidgetItem(QStringList() << "Class: IN (0x000" + QString::number(Class) + ")"));
	}
	int answerNumber = answer.toUtf8().toInt();
	if (answerNumber > 0) {
		QTreeWidgetItem* answerTree = new QTreeWidgetItem(QStringList() << "Answers");
		info.append(answerTree);
		for (int i = 0; i < answerNumber; i++) {
			QString name1;
			QString name2;
			u_short type;
			u_short Class;
			u_int ttl;
			u_short length;

			int tempOffset = getDnsAnswersDomain(offset, name1, type, Class, ttl, length, name2);
			QString sType = getDnsDomainType(type);
			QString temp = "";
			if (type == 1) temp = "addr";
			else if (type == 5) temp = "cname";
			QTreeWidgetItem* answerSubTree = new QTreeWidgetItem(QStringList() << name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
			answerTree->addChild(answerSubTree);
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << "Name:" + name1));
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << "Type:" + sType + "(" + QString::number(type) + ")"));
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << "Class: IN (0x000" + QString::number(Class) + ")"));
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << "Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << "Data length:" + QString::number(length)));
			answerSubTree->addChild(new QTreeWidgetItem(QStringList() << sType + ":" + name2));

			offset += tempOffset;
		}
	}
	return info;
}

QList<QTreeWidgetItem*> DataPackage::getDnsFlagInfo()
{
	QList<QTreeWidgetItem*> info;
	info.append(new QTreeWidgetItem(QStringList() << "Response: " + getDnsFlagsQR()));
	info.append(new QTreeWidgetItem(QStringList() << "Opcode: " + getDnsFlagsOpcode()));
	info.append(new QTreeWidgetItem(QStringList() << "Authoritative: " + getDnsFlagsAA()));
	info.append(new QTreeWidgetItem(QStringList() << "Truncated: " + getDnsFlagsTC()));
	info.append(new QTreeWidgetItem(QStringList() << "Recursion Desired: " + getDnsFlagsRD()));
	info.append(new QTreeWidgetItem(QStringList() << "Recursion Available: " + getDnsFlagsRA()));
	info.append(new QTreeWidgetItem(QStringList() << "Z: " + getDnsFlagsZ()));
	info.append(new QTreeWidgetItem(QStringList() << "Reply code: " + getDnsFlagsRcode()));
	return info;
}

QString DataPackage::getDnsId()
{
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	u_short id = NTOHS(dns->_id);
	return "Transaction ID: 0x" + QString::number(id, 16);
}

QString DataPackage::getDnsFlags() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	int type = ntohs(dns->_flag);
	QString info = "";
	if ((type & 0xf800) == 0x0000) {
		info = "(Standard query)";
	}
	else if ((type & 0xf800) == 0x8000) {
		info = "(Standard query response)";
	}
	return "0x" + QString::number(type, 16) + info;
}

QString DataPackage::getDnsFlagsQR() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	u_char qr = (ntohs(dns->_flag) & 0x8000) >> 15;
	QString res = QString::number(qr);
	if (qr == 0)
	{
		res += " Message is a query";
	}
	else if (qr == 1)
	{
		res += " Message is a response";
	}
	return res;
}

QString DataPackage::getDnsFlagsOpcode() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);

	return QString::number((ntohs(dns->_flag) & 0x7800) >> 11);
}

QString DataPackage::getDnsFlagsAA() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number((ntohs(dns->_flag) & 0x0400) >> 10);
}

QString DataPackage::getDnsFlagsTC() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	u_char TC = (ntohs(dns->_flag) & 0x0200) >> 9;
	QString res = "Message is ";
	if (TC == 0)
	{
		res += "not truncated (" + QString::number(TC) + ")";
	}
	else if (TC == 1)
	{
		res += "truncated (" + QString::number(TC) + ")";
	}
	return res;
}

QString DataPackage::getDnsFlagsRD() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	u_char RD = (ntohs(dns->_flag) & 0x0100) >> 8;
	QString res = "";
	if (RD == 0)
	{
		res = "Don't do query recursively (" + QString::number(RD) + ")";
	}
	else if (RD == 1)
	{
		res = "Do query recursively (" + QString::number(RD) + ")";
	}
	return res;
}

QString DataPackage::getDnsFlagsRA() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number((ntohs(dns->_flag) & 0x0080) >> 7);
}

QString DataPackage::getDnsFlagsZ() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number((ntohs(dns->_flag) & 0x0070) >> 4);
}

QString DataPackage::getDnsFlagsRcode() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number((ntohs(dns->_flag) & 0x000f));
}

QString DataPackage::getDnsQuestionNumber() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number(ntohs(dns->_ques));
}

QString DataPackage::getDnsAnswerNumber() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number(ntohs(dns->_ans));
}

QString DataPackage::getDnsAuthorityNumber() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number(ntohs(dns->_auth));
}

QString DataPackage::getDnsAdditionalNumber() {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	return QString::number(ntohs(dns->_add));
}

void DataPackage::getDnsQueriesDomain(QString& name, int& Type, int& Class) {
	DNS_HEADER* dns;
	dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
	char* domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
	while (*domain != 0x00) {
		if (domain && (*domain) <= 64) {
			int length = *domain;
			domain++;
			for (int k = 0; k < length; k++) {
				name += (*domain);
				domain++;
			}
			name += ".";
		}
		else break;
	}
	domain++;
	name = name.left(name.length() - 1);
	DNS_QUESITON* qus = (DNS_QUESITON*)(domain);
	Type = ntohs(qus->query_type);
	Class = ntohs(qus->query_class);
}

QString DataPackage::getDnsDomainName(int offset) {
	char* dns;
	dns = (char*)(pkt_content + 14 + 20 + 8 + offset);
	QString name = "";
	while (dns && *dns != 0x00) {
		if ((unsigned char)(*dns) <= 64) {
			int length = *dns;
			dns++;
			for (int k = 0; k < length; k++) {
				name += (*dns);
				dns++;
			}
			name += ".";
		}
		else if (((*dns) & 0xc0) == 0xc0) {
			int accOffset = (((*dns) & 0x3f) << 8);
			dns++;
			accOffset += (unsigned char)(*dns);
			name += getDnsDomainName(accOffset) + ".";
			dns++;
			break;
		}
	}
	name = name.left(name.length() - 1);
	return name;
}

int DataPackage::getDnsAnswersDomain(int offset, QString& name1, u_short& Type, u_short& Class, u_int& ttl, u_short& dataLength, QString& name2) {
	char* dns = (char*)(pkt_content + 14 + 20 + 8 + 12 + offset);
	if (((*dns) & 0xc0) == 0xc0) {
		int accOffset = (((*dns) & 0x3f) << 8);
		dns++; //
		accOffset += (*dns);
		name1 = getDnsDomainName(accOffset);
		dns++; //
		DNS_ANSWER* answer = (DNS_ANSWER*)(dns);
		Type = ntohs(answer->answer_type);
		Class = ntohs(answer->answer_class);
		ttl = ntohl(answer->TTL);
		dataLength = ntohs(answer->dataLength);
		dns += (2 + 2 + 4 + 2);
		if (dataLength == 4) {
			for (int i = 0; i < 4; i++) {
				name2 += QString::number((unsigned char)(*dns));
				name2 += ".";
				dns++;
			}
		}
		else {
			for (int k = 0; k < dataLength; k++) {
				if ((unsigned char)(*dns) <= 64) {
					int length = *dns;
					dns++;
					k++;
					for (int j = 0; j < length; j++) {
						name2 += *dns;
						dns++;
						k++;
					}
					name2 += ".";
				}
				else if (((*dns) & 0xc0) == 0xc0) {
					int accOffset = (((*dns) & 0x3f) << 8);
					dns++;
					k++;
					accOffset += (unsigned char)(*dns);
					name2 += getDnsDomainName(accOffset) + ".";
					dns++;
					k++;
				}
			}
		}
		name2 = name2.left(name2.length() - 1);
		return dataLength + 2 + 2 + 2 + 4 + 2;

	}
	else {
		name1 = getDnsDomainName(offset + 12);
		DNS_ANSWER* answer = (DNS_ANSWER*)(dns + name1.size() + 2);
		Type = ntohs(answer->answer_type);
		Class = ntohs(answer->answer_class);
		ttl = ntohl(answer->TTL);
		dataLength = ntohs(answer->dataLength);
		if (dataLength == 4) {
			dns += (2 + 2 + 4 + 2 + name1.size() + 1);
			for (int i = 0; i < 4; i++) {
				name2 += (unsigned char)(*dns);
				dns++;
			}
		}
		else {
			for (int k = 0; k < dataLength; k++) {
				if ((unsigned char)(*dns) <= 64) {
					int length = *dns;
					dns++;
					k++;
					for (int j = 0; j < length; j++) {
						name2 += *dns;
						dns++;
						k++;
					}
					name2 += ".";
				}
				else if (((*dns) & 0xc0) == 0xc0) {
					int accOffset = (((*dns) & 0x3f) << 8);
					dns++;
					k++;
					accOffset += (*dns);
					name2 += getDnsDomainName(accOffset);
					dns++;
					k++;
				}
			}
		}
		name2 = name2.left(name2.length() - 1);
		return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
	}
}

QString DataPackage::getDnsDomainType(int type) {
	switch (type) {
	case 1: return "A (Host Address)";
	case 2:return "NS";
	case 5:return "CNAME (Canonical NAME for an alias)";
	case 6:return "SOA";
	case 11:return "WSK";
	case 12:return "PTR";
	case 13:return "HINFO";
	case 15:return "MX";
	case 28:return "AAAA";
	case 252:return "AXFR";
	case 255:return "ANY";
	default:return "";
	}
}

QString DataPackage::byteToString(u_char* str, int size)
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