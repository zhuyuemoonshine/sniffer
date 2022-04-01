#ifndef MYPCAP_H
#define MYPCAP_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
using namespace std;

#define SIZE 1024
#define ushort unsigned short
#define uint unsigned int



extern pcap_if_t* allNetwork;     // ������Ϣ
extern int                      size;           // ��������
extern char                     errbuf[SIZE];   // ������Ϣ
extern pcap_t* sniff;          // ��̽
extern struct pcap_pkthdr* packHeader;     // ���ݰ�ͷ
extern const u_char* packData;       // ���ݱ�
extern const int                packSum;        // ���ѭ��ץȡ���ݰ��Ĵ���

// ��̫��֡ͷ����Ϣ
struct ether_parse {
    string _decs;       // Ŀ��MAC ��ַ
    string _src;        // Դ  MAC ��ַ
    string _type;       // �ϲ�Э������
    string _str;        // 16�����ַ�����Ϣ
};
extern ether_parse* eth_protocal;  // ��̫��Э��

// ip Э��
struct ip_parse {
    string      _version;           // �汾
    string      _handerLen;         // �ײ�����
    string      _diffserv;          // ���ַ���
    string      _totalLen;          // �ܳ���
    string      _identification;    // ��ʶ
    string      _flag_offset;       // ��־ 3 + Ƭƫ�� 13
    string      _timeLive;          // ����ʱ��
    string      _protocol;          // Э��
    string      _checkSum;          // �ײ�У���
    string      _src;               // Դ��ַ
    string      _desc;              // Ŀ�ĵ�ַ
    string      _str[4];            // 16�����ַ�����Ϣ����
};
extern ip_parse* ip_protocal;       // ip Э��

// udp Э��  �����
struct udp_parse {
    string      _sport;             // Դ�˿�
    string      _dport;             // Ŀ�Ķ˿�
    string      _len;               // ���ݳ���
    string      _checksum;          // У���
    string      _str[2];            // 16�����ַ�����Ϣ����
};
extern udp_parse* udp_protocal;     // udp Э��

// tcp Э��  �����
struct tcp_parse {
    string      _sport;             // Դ�˿�
    string      _dport;             // Ŀ�Ķ˿�
    string      _seqNum;            // ���к�
    string      _ackNum;            // ȷ�Ϻ�
    string      _off_res_flag;      // ����ƫ�� 4  ����λ 6  ��־λ 6
    string      _winSize;           // ���ڴ�С
    string      _checkSum;          // У���
    string      _urgentPoint;       // ����ָ��
    string      _str[5];            // 16�����ַ�����Ϣ����
};
extern tcp_parse* tcp_protocal;     // tcp Э��

// ��ȡ������Ϣ
//bool infoNetwork();

// ������̽��ȡ���ݰ�  cnt ������̽���
bool setSniffing(int cnt, pcap_if_t* alldevs);

// ��ȡ���ݰ�
bool getDataPacket(int packSum);



// ����������·��
bool ParseDateLine();


// ���������
bool ParseNetWork();

// ��������� 0 �������  1 ����TCP  2 ����UDP  3 ����ICMP
bool ParseTransport();

// ����TCPЭ��
bool ParseTCP();

// ����UDPЭ��
bool ParseUDP();

// ����ICMPЭ��
bool ParseICMP();


#endif // MYPCAP_H