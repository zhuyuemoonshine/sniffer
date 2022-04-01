#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char; //1字节
typedef unsigned short u_short;//2字节
typedef unsigned int u_int;//4字节
typedef unsigned long u_long;//4字节

//mac头部信息
typedef struct ether_header {
    u_char  _ether_dhost[6];    // 目标地址
    u_char  _ether_shost[6];    // 源地址
    u_short _ether_type;        // 类型
}ETHER_HEADER;

//ip头部信息
typedef struct ip_header {
    u_char      _version_headerLen;     // 版本 4bit  首部长度 4bit
    u_char      _diffserv;              // 服务类型
    u_short     _totalLen;              // 总长度
    u_short     _identification;        // 标识
    u_short     _flag_offset;           // 标志 3 + 片偏移 13
    u_char      _timeLive;              // 生存时间
    u_char      _protocol;              // 协议
    u_short     _checkSum;              // 首部校验和
    u_int       _src;                   // 源地址
    u_int       _desc;                  // 目的地址
}IP_HEADER;


//Tcp头部信息
typedef struct tcp_header {
    u_short      _sport;         // 源端口
    u_short      _dport;         // 目的端口
    u_int        _seqNum;        // 序列号
    u_int        _ackNum;        // 确认号
    u_short      _off_res_flag;  // 数据偏移 4  保留位 6  标志位 6
    u_short      _winSize;       // 窗口大小
    u_short      _checkSum;      // 校验和
    u_short      _urgentPoint;   // 紧急指针
}TCP_HEADER;

//Udp头部信息
typedef struct udp_header {
    u_short      _sport;     // 源端口
    u_short      _dport;     // 目的端口
    u_short      _len;       // 数据长度
    u_short      _checksum;  // 校验和
}UDP_HEADER;

//icmp头部信息
typedef struct icmp_header {
    u_char      _type;              // icmp 类型
    u_char      _code;              // 代码
    u_short     _checkSum;          // 校验和
    u_short     _identification;    // 标识
    u_short     _seq;               // 序列号
}ICMP_HEADER;

//arp头部信息
typedef struct arp_header {
    u_short     _type;                  //硬件类型
    u_short     _protocol;              //协议类型
    u_char      _mac_len;                //硬件地址长度
    u_char      _ip_len;                 //协议地址长度
    u_short     _op_type;                //操作类型

    u_char      _src_ether_addr[6];     // 源mac地址    
    u_char      _src_ip_addr[4];        // 源ip地址    
    u_char      _des_ether_addr[6];     // 目的mac地址
    u_char      _des_ip_addr[4];        // 目的ip地址

}ARP_HEADER;


//DNS头部信息
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
