#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char; //1�ֽ�
typedef unsigned short u_short;//2�ֽ�
typedef unsigned int u_int;//4�ֽ�
typedef unsigned long u_long;//4�ֽ�

//macͷ����Ϣ
typedef struct ether_header {
    u_char  _ether_dhost[6];    // Ŀ���ַ
    u_char  _ether_shost[6];    // Դ��ַ
    u_short _ether_type;        // ����
}ETHER_HEADER;

//ipͷ����Ϣ
typedef struct ip_header {
    u_char      _version_headerLen;     // �汾 4bit  �ײ����� 4bit
    u_char      _diffserv;              // ��������
    u_short     _totalLen;              // �ܳ���
    u_short     _identification;        // ��ʶ
    u_short     _flag_offset;           // ��־ 3 + Ƭƫ�� 13
    u_char      _timeLive;              // ����ʱ��
    u_char      _protocol;              // Э��
    u_short     _checkSum;              // �ײ�У���
    u_int       _src;                   // Դ��ַ
    u_int       _desc;                  // Ŀ�ĵ�ַ
}IP_HEADER;


//Tcpͷ����Ϣ
typedef struct tcp_header {
    u_short      _sport;         // Դ�˿�
    u_short      _dport;         // Ŀ�Ķ˿�
    u_int        _seqNum;        // ���к�
    u_int        _ackNum;        // ȷ�Ϻ�
    u_short      _off_res_flag;  // ����ƫ�� 4  ����λ 6  ��־λ 6
    u_short      _winSize;       // ���ڴ�С
    u_short      _checkSum;      // У���
    u_short      _urgentPoint;   // ����ָ��
}TCP_HEADER;

//Udpͷ����Ϣ
typedef struct udp_header {
    u_short      _sport;     // Դ�˿�
    u_short      _dport;     // Ŀ�Ķ˿�
    u_short      _len;       // ���ݳ���
    u_short      _checksum;  // У���
}UDP_HEADER;

//icmpͷ����Ϣ
typedef struct icmp_header {
    u_char      _type;              // icmp ����
    u_char      _code;              // ����
    u_short     _checkSum;          // У���
    u_short     _identification;    // ��ʶ
    u_short     _seq;               // ���к�
}ICMP_HEADER;

//arpͷ����Ϣ
typedef struct arp_header {
    u_short     _type;                  //Ӳ������
    u_short     _protocol;              //Э������
    u_char      _mac_len;                //Ӳ����ַ����
    u_char      _ip_len;                 //Э���ַ����
    u_short     _op_type;                //��������

    u_char      _src_ether_addr[6];     // Դmac��ַ    
    u_char      _src_ip_addr[4];        // Դip��ַ    
    u_char      _des_ether_addr[6];     // Ŀ��mac��ַ
    u_char      _des_ip_addr[4];        // Ŀ��ip��ַ

}ARP_HEADER;


//DNSͷ����Ϣ
typedef struct dns_header {
    u_short _id;
    u_short _flag;
    u_short _ques;
    u_short _ans;
    u_short _auth;
    u_short _add;
}DNS_HEADER;

typedef struct dns_question {
    u_short query_type;     
    u_short query_class;    
}DNS_QUESITON;

typedef struct dns_answer {
    u_short answer_type;   
    u_short answer_class;  
    u_int TTL;             
    u_short dataLength;    
}DNS_ANSWER;

#endif
