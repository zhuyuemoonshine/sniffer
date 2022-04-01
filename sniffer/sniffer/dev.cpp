#include"dev.h";




pcap_if_t* getDev() 
{
	pcap_if_t* alldevs;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 获取本地网卡信息 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL , &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	else
	{
		return alldevs;
	}
}

void printDev(pcap_if_t* alldevs) 
{
	pcap_if_t* d;
	int i = 0;
	/* 打印网卡列表 */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return;
	}
}