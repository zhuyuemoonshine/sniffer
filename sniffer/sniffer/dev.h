#ifndef _DEV_H_
#define _DEV_H_

#include "pcap.h"
using namespace std;

pcap_if_t* getDev();
void printDev(pcap_if_t* alldevs);


#endif