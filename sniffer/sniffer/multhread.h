#pragma once
#include <QThread>
#include <winsock2.h>
#include "pcap.h"
#include "Format.h"
#include "DataPackage.h"

class multhread:public QThread
{
	Q_OBJECT
public:
	multhread();
	bool setPointer(pcap_t* pointer);
	void setFlag();
	void resetFlag();
	void run() override;
	int ethernetPackageHandle(const u_char* pkt_content, QString &info);
	int ipPackageHandle(const u_char* pkt_content, int& ipPackage);
	int tcpPackageHandle(const u_char* pkt_content, QString& info, int ipPackage);
	int udpPackageHandle(const u_char* pkt_content, QString& info);
	int icmpPackageHandle(const u_char* pkt_content, QString& info);
	QString arpPackageHandle(const u_char* pkt_content);
	QString dnsPackageHandle(const u_char* pkt_content);
	QString byteToString(u_char* str, int size);

#define NTOHS(A) ((((A)&0xFF00)>>8) | (((A)&0x00FF)<<8))
#define NTOHSL(A) ((((A) & 0xff000000) >> 24) | \
				   (((A) & 0x00ff0000) >>  8) | \
				   (((A) & 0x0000ff00) <<  8) | \
				   (((A) & 0x000000ff) << 24))

signals:
	void send(DataPackage data);

private:
	pcap_t* pointer;
	struct pcap_pkthdr* packHeader;
	const u_char* packData;
	time_t local_time_sec;
	struct tm local_time;
	char timeString[16];
	bool isDone;
};

