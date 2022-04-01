#pragma once

#include "Format.h"
#include <QString>
#include <winsock2.h>
#include <QTreeWidget>


class DataPackage
{
public:
	DataPackage();
	void setDataLength(u_int data_length);
	void setTimeStmp(QString timeStmp);
	void setInfo(QString info);
	void setPackageType(int type);
	void setPointer(const u_char* pkt_content,int size);

	QString getDataLength();
	QString getTimeStmp();
	QString getInfo();
	QString getPackageType();
	QString getSource();
	QString getDestination();

	u_int getDataLengthInt();
	int getPackageTypeInt();

	QString getDesMacAddr();
	QString getSrcMacAddr();
	QString getMacType();


	QList<QTreeWidgetItem*> getIp();
	QString getDesIpAddr();
	QString getSrcIpAddr();
	QString getIpVersion();
	QString getIpHeaderLength();
	QString getIpTotalLength();
	QString getIpTTL();
	QString getIpProtocol();


	QList<QTreeWidgetItem*> getArp();
	QString getArpHType();
	QString getArpOp();
	QString getArpPType();
	QString getArpSMacAddr();
	QString getArpTMacAddr();
	QString getArpSIpAddr();
	QString getArpTIpAddr();

	QString getTcpSrcPort();
	QString getTcpDesPort();
	QString getTcpSeq();
	QString getTcpAck();

	QString getUdpSrcPort();
	QString getUdpDesPort();
	QString getUdpLength();

	QList<QTreeWidgetItem*> getIcmp();
	QString getIcmpType();
	QString getIcmpCode();
	QString getIcmpCheckSum();
	QString getIcmpId();
	QString getIcmpSeq();


	QList<QTreeWidgetItem*> getDns();
	QList<QTreeWidgetItem*> getDnsFlagInfo();
	QString getDnsId();
	QString getDnsFlags();                    
	QString getDnsFlagsQR();                  
	QString getDnsFlagsOpcode();              
	QString getDnsFlagsAA();                  
	QString getDnsFlagsTC();                  
	QString getDnsFlagsRD();                  
	QString getDnsFlagsRA();                  
	QString getDnsFlagsZ();
	QString getDnsFlagsRcode();
	QString getDnsQuestionNumber();           
	QString getDnsAnswerNumber();             
	QString getDnsAuthorityNumber();          
	QString getDnsAdditionalNumber();  
	void getDnsQueriesDomain(QString& name, int& Type, int& Class);
	QString getDnsDomainType(int type);
	QString getDnsDomainName(int offset);
	int getDnsAnswersDomain(int offset, QString& name1, u_short& Type, u_short& Class, u_int& ttl, u_short& dataLength, QString& name2);


	QString iptos(u_int in);
#define NTOHS(A) ((((A)&0xFF00)>>8) | (((A)&0x00FF)<<8))
#define NTOHSL(A) ((((A) & 0xff000000) >> 24) | \
				   (((A) & 0x00ff0000) >>  8) | \
				   (((A) & 0x0000ff00) <<  8) | \
				   (((A) & 0x000000ff) << 24))

private:
	u_int data_length;
	QString timeStmp;
	QString info;
	int package_type;

protected:
	static QString byteToString(u_char* str, int size);
public:
	const u_char* pkt_content;
};

