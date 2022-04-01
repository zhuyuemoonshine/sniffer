#include "mypcap.h";

//pcap_if_t* allNetwork = nullptr;     // ������Ϣ
int                 size = 0;            // ��������
char                errbuf[SIZE];                   // ������Ϣ
pcap_t* sniff = nullptr;      // ��̽
struct pcap_pkthdr* packHeader = nullptr;      // ���ݰ�ͷ
const u_char* packData = nullptr;      // ���ݱ�
//const int           packSum = 10;            // ���ѭ��ץȡ���ݰ��Ĵ���

ether_parse* eth_protocal = nullptr;         // ��̫��Э��
ip_parse* ip_protocal = nullptr;         // ip Э��
udp_parse* udp_protocal = nullptr;         // udp Э��
tcp_parse* tcp_protocal = nullptr;         // tcp Э��

// ������̽��ȡ���ݰ�  cnt ������̽���
bool setSniffing(int cnt ,pcap_if_t* alldevs) {
    if (cnt < 0) return false;

    // �õ�ָ����̽
    pcap_if_t* adapters = alldevs;

    for (int i = 0; i < cnt && adapters; i++) {
        adapters = adapters->next;
    }
    if (adapters == nullptr) return false;

    cout << adapters->description << endl;
        // ��ǰץ��ʹ�õ���̽Ϊ pcap_if_t* curAdapter
    pcap_if_t* curAdapter = adapters;
    #define  MAXDATAFRAMES 1518

    // Ϊ����/�������ݴ�һ����ͨ��Դ
    // PCAP_OPENFLAG_PROMISCUOUS ��������Ϊ���ģʽ
    // 1000 1000����������������ݾͳ�ʱ����
    ::sniff = pcap_open(curAdapter->name, MAXDATAFRAMES, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, ::errbuf);
    if (pcap_datalink(::sniff) != DLT_EN10MB) return false;      // ��������̫��Э��
    return ::sniff != nullptr;
}

// ��ȡ���ݰ�
bool getDataPacket(int packSum) {
    int num = 0;
    while (num++ < packSum) {
        int ret = pcap_next_ex(sniff, &(::packHeader), &(::packData));
        if (ret != 1) continue;  // ����ʧ�ܣ�ѭ������
        ParseDateLine();
        if (::eth_protocal->_type == "0x800") {
            ParseNetWork();
            ParseTransport();
        }
        // ����ɹ�
        //return true;
    }
    return true;
}

// itoa ��װ��תΪָ�����Ƶ�sting ����
char buf[SIZE / 2];
template <class T>
string dataToString(T data, int radix) {
    memset(buf, 0x00, sizeof buf);
    _itoa_s(data, buf, radix);
    return buf;
}


// ����������·��

bool ParseDateLine() {
    // ��̫������֡ͷ��ʽ
    struct ether_hander {
        u_char  _ether_dhost[6];    // Ŀ���ַ
        u_char  _ether_shost[6];    // Դ��ַ
        u_short _ether_type;        // ����
    };
    ether_hander* handl = (ether_hander*)::packData;      // �õ���̫��֡ͷ
    ::eth_protocal = new ether_parse();                 // תΪ��ʾ�ĸ�ʽ

#define NTOHS(A) ((((A)&0xFF00)>>8) | (((A)&0x00FF)<<8))
    handl->_ether_type = NTOHS(handl->_ether_type);  // �����ֽ���תΪ�����ֽ���

    // ��̫��Э������
    (::eth_protocal)->_type = "0x" + dataToString(handl->_ether_type, 16);
    //if ((::eth_protocal)->_type != "0x800") return false;    // ����㲻��ipЭ��

    // Ŀ���ַ MAC
    memset(buf, 0x00, sizeof buf);
#define A(I) handl->_ether_dhost[I]
    sprintf_s(buf,512, " %02X:%02X:%02X:%02X:%02X:%02X", A(0), A(1), A(2), A(3), A(4), A(5));
    (::eth_protocal)->_decs = buf;

    // Դ��ַ MAC
    memset(buf, 0x00, sizeof buf);
#define B(I) handl->_ether_shost[I]
    sprintf_s(buf, 512," %02X:%02X:%02X:%02X:%02X:%02X ", B(0), B(1), B(2), B(3), B(4), B(5));
    (::eth_protocal)->_src = buf;

    // ԭ����
    (::eth_protocal)->_str += "0x";
    for (int i = 0; i < 6; i++) {
        string t = dataToString(handl->_ether_dhost[i], 16);
        (::eth_protocal)->_str += string("0", 2 - t.size()) + t + " ";
    }

    for (int i = 0; i < 6; i++) {
        string t = dataToString(handl->_ether_shost[i], 16);
        (::eth_protocal)->_str += string("0", 2 - t.size()) + t + " ";
    }
    string t = dataToString(handl->_ether_type, 16);
    (::eth_protocal)->_str += string("0", 4 - t.size()) + t;
    return true;
}

// ���ʮ����
string iptos(long in)
{
    u_char* p;
    p = (u_char*)&in;
    memset(buf, 0x00, sizeof buf);
    sprintf_s(buf,512 , "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return buf;
}

// ���������
bool ParseNetWork() {
    struct ip_hander {
        u_char      _version_handerLen;     // �汾 4  �ײ����� 4
        u_char      _diffserv;              // ��������
        u_short     _totalLen;              // �ܳ���
        u_short     _identification;        // ��ʶ
        u_short     _flag_offset;           // ��־ 3 + Ƭƫ�� 13
        u_char      _timeLive;              // ����ʱ��
        u_char      _protocol;              // Э��
        u_short     _checkSum;              // �ײ�У���
        long        _src;                   // Դ��ַ
        long        _desc;                  // Ŀ�ĵ�ַ
    };

    ip_hander* handl = (ip_hander*)(::packData + 14);
    ::ip_protocal = new ip_parse();

    // ip �汾 ipv4  ipv6
    if ((handl->_version_handerLen & (0x40)) == 0x40) (::ip_protocal)->_version = "ipv4";
    else if ((handl->_version_handerLen & (0x60)) == 0x60) (::ip_protocal)->_version = "ipv6";
    else return false;


    char len = handl->_version_handerLen & 0x0f;
    if (len < 0x05) return false;    //���ڹ̶�����
    (::ip_protocal)->_handerLen = "0x" + dataToString(len, 16);                              // �ײ�����
    (::ip_protocal)->_diffserv = "0x" + dataToString(handl->_diffserv, 16);                 // ��������
    (::ip_protocal)->_totalLen = "0x" + dataToString(handl->_totalLen, 16);                 // �ܳ���
    (::ip_protocal)->_identification = "0x" + dataToString(handl->_identification, 16);     // ��ʶ


    char flag = (handl->_flag_offset) >> 13;
    string fRet = dataToString(flag, 2);
    fRet = string(3 - fRet.size(), '0') + fRet; // ��ǰ��0
    char offset = handl->_flag_offset & 0x1fff;
    string oRet = dataToString(offset, 16);
    oRet = string(4 - oRet.size(), '0') + oRet;
    (::ip_protocal)->_flag_offset = fRet + "  " + "0x" + oRet;                   // ��־ 3 Ƭƫ�� 13
    (::ip_protocal)->_timeLive = dataToString(handl->_timeLive, 10);      // ����ʱ��
    (::ip_protocal)->_protocol = dataToString(handl->_protocol, 10);             // Э��
    (::ip_protocal)->_checkSum = "0x" + dataToString(handl->_checkSum, 16);      // �ײ�У���
    (::ip_protocal)->_src = iptos(handl->_src);                               // Դ��ַ
    (::ip_protocal)->_desc = iptos(handl->_desc);                              // Ŀ���ַ


#define FUN(S,N) string(N - S.size(),'0') + S
    (::ip_protocal)->_str[0] = "0x" + FUN(dataToString(handl->_version_handerLen, 16), 2) + " " + FUN(dataToString(handl->_diffserv, 16), 2) + " " + FUN(dataToString(handl->_totalLen, 16), 4);
    (::ip_protocal)->_str[1] = "0x" + FUN(dataToString(handl->_identification, 16), 4) + " " + FUN(dataToString(handl->_flag_offset, 16), 4);
    (::ip_protocal)->_str[2] = "0x" + FUN(dataToString(handl->_timeLive, 16), 2) + " " + FUN(dataToString(handl->_protocol, 16), 2) + " " + FUN(dataToString(handl->_checkSum, 16), 4);
    return true;
}

// ��������� 0 �������  1 ����TCP  2 ����UDP
bool ParseTransport() {
    bool ret = false;
    int flag = atoi(::ip_protocal->_protocol.c_str());
    if (flag == 1 || flag == 6 || flag == 17)
    {
        cout << "ʱ�����" << packHeader->ts.tv_sec << endl;
        cout << "Ŀ��mac��ַ:" << ::eth_protocal->_decs << endl;
        cout << "Դmac��ַ" << ::eth_protocal->_src << endl;
        cout << "ԭ���ݣ�" << ::eth_protocal->_str << endl;
        cout << "ip�汾��" << ::ip_protocal->_version << endl;
        cout << "Դip��ַ" << ::ip_protocal->_src << endl << "Ŀ��ip��ַ" << ::ip_protocal->_desc << endl;
        if (flag == 1) {
            cout << "ICMPЭ��" << endl << endl;
            ret = ParseICMP();
        }
        else if (flag == 6) {
            cout << "TCPЭ��" << endl << endl;
            ret = ParseTCP();
        }
        else if (flag == 17) {
            cout << "UDPЭ��" << endl << endl;
            ret = ParseUDP();
        }
    }
    
    return ret;
}

// ����TCPЭ��
bool ParseTCP() {
    struct TCP_hander {
        ushort      _sport;         // Դ�˿�
        ushort      _dport;         // Ŀ�Ķ˿�
        uint        _seqNum;        // ���к�
        uint        _ackNum;        // ȷ�Ϻ�
        ushort      _off_res_flag;  // ����ƫ�� 4  ����λ 6  ��־λ 6
        ushort      _winSize;       // ���ڴ�С
        ushort      _checkSum;      // У���
        ushort      _urgentPoint;   // ����ָ��
    };

    TCP_hander* handl = (TCP_hander*)(::packData + 14 + 20);  // ��̫��֡ͷ14 ipͷ�� 20
    ::tcp_protocal = new tcp_parse();

    (::tcp_protocal)->_sport = "0x" + dataToString(handl->_sport, 16) + "(" + to_string(handl->_sport) + ") ";         // Դ�˿�
    (::tcp_protocal)->_dport = "0x" + dataToString(handl->_dport, 16) + "(" + to_string(handl->_dport) + ") ";         // Ŀ�Ķ˿�
    (::tcp_protocal)->_seqNum = "0x" + dataToString(handl->_seqNum, 16) + "(" + to_string(handl->_seqNum) + ") ";       // ���к�
    (::tcp_protocal)->_ackNum = "0x" + dataToString(handl->_ackNum, 16) + "(" + to_string(handl->_ackNum) + ") ";       // ȷ�Ϻ�

    string offset = dataToString((handl->_off_res_flag & 0xf000) >> 12, 2);
    (::tcp_protocal)->_off_res_flag = string(4 - offset.size(), '0') + offset;               // 4 ����ƫ��

    string reserve = dataToString((handl->_off_res_flag & 0x0fC0) >> 6, 2);
    (::tcp_protocal)->_off_res_flag += " " + string(6 - reserve.size(), '0') + reserve;      // 6 λ����λ

    string flag = dataToString((handl->_off_res_flag & 0x003f), 2);
    (::tcp_protocal)->_off_res_flag += " " + string(6 - flag.size(), '0') + flag;            // 6 λ��־

    (::tcp_protocal)->_winSize = "0x" + dataToString(handl->_winSize, 16);         // ���ڴ�С
    (::tcp_protocal)->_checkSum = "0x" + dataToString(handl->_checkSum, 16);        // У���
    (::tcp_protocal)->_urgentPoint = "0x" + dataToString(handl->_urgentPoint, 16);  // ����ָ��

#define FUN(S,N) string(N - S.size(),'0') + S
    (::tcp_protocal)->_str[0] = "0x" + FUN(dataToString(handl->_sport, 16), 4) + " " + FUN(dataToString(handl->_dport, 16), 4);
    (::tcp_protocal)->_str[1] = "0x" + FUN(dataToString(handl->_seqNum, 16), 8);
    (::tcp_protocal)->_str[2] = "0x" + FUN(dataToString(handl->_ackNum, 16), 8);
    (::tcp_protocal)->_str[3] = "0x" + FUN(dataToString(handl->_off_res_flag, 16), 4) + " " + FUN(dataToString(handl->_winSize, 16), 4);
    (::tcp_protocal)->_str[4] = "0x" + FUN(dataToString(handl->_checkSum, 16), 4) + " " + FUN(dataToString(handl->_urgentPoint, 16), 4);
    return true;
}

// ����UDPЭ��
bool ParseUDP() {
    struct UDP_handler {
        ushort      _sport;     // Դ�˿�
        ushort      _dport;     // Ŀ�Ķ˿�
        ushort      _len;       // ���ݳ���
        ushort      _checksum;  // У���
    };

    UDP_handler* handl = (UDP_handler*)(::packData + 14 + 20);      // ��̫��֡ͷ14 ipͷ�� 20
    ::udp_protocal = new udp_parse();

    (::udp_protocal)->_sport = "0x" + dataToString(handl->_sport, 16) + "(" + to_string(handl->_sport) + ")";       // Դ�˿�
    (::udp_protocal)->_dport = "0x" + dataToString(handl->_dport, 16) + "(" + to_string(handl->_dport) + ")";       // Ŀ�Ķ˿�
    (::udp_protocal)->_len = "0x" + dataToString(handl->_len, 16);         // ���ݰ�����
    (::udp_protocal)->_checksum = "0x" + dataToString(handl->_checksum, 16);    // udpУ���

#define FUN(S,N) string(N - S.size(),'0') + S
    (::udp_protocal)->_str[0] = "0x" + FUN(dataToString(handl->_sport, 16), 4) + " " + FUN(dataToString(handl->_dport, 16), 4);
    (::udp_protocal)->_str[1] = "0x" + FUN(dataToString(handl->_len, 16), 4) + " " + FUN(dataToString(handl->_checksum, 16), 4);
    return true;
}

// ICMP Э��
bool ParseICMP() {
    struct icmp_handler {
        u_char      _type;              // icmp ����
        u_char      _code;              // ����
        u_short     _checkSum;          // У���
        u_short     _identification;    // ��ʶ
        u_short     _seq;               // ���к�
        uint        _initTime;          // ����ʱ���
        u_short     _recvTime;          // ����ʱ���
        u_short     _sendTime;          // ����ʱ���
    };

    return true;
}