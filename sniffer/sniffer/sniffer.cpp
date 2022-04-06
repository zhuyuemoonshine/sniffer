#include "sniffer.h"
#include <QString>
#include <QDebug>
#include "multhread.h"
#include "filter.h"

sniffer::sniffer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
	statusBar()->showMessage("welcome!");
	ui.toolBar->addAction(ui.actionrun);
	ui.toolBar->addAction(ui.actionempty);
	countNumber = 0;
	showNetworkCards();	
	showProtocols();
	multhread* thread = new multhread;
	static bool index = false;
	fi = false;
	filt = new filter;
	connect(ui.comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(on_comboBox_currentIndexChanged(int index)));
	connect(ui.tableWidget, SIGNAL(cellClicked(int int)), this, SLOT(on_tableWidget_cellClicked(int  row, int column)));
	connect(ui.comboBox_2, SIGNAL(currentIndexChanged(QString)), this, SLOT(on_comboBox_2_currentIndexChanged(QString pro)));
	connect(ui.actionrun, &QAction::triggered, this, [=]() {
		index = !index;
		if (index) 
		{
			ui.tableWidget->clearContents();
			ui.tableWidget->setRowCount(0);
			countNumber = 0;
			numberRow = -1;
			filt->quit();
			int dataSize = this->pData.size();
			for (int i = 0; i < dataSize; i++)
			{
				free((char*)(this->pData[i].pkt_content));
				this->pData[i].pkt_content = nullptr;
			}
			QVector<DataPackage>().swap(pData);
			
			int ret = capture();
			if (ret != -1 && pointer)
			{
				if (fi == true)
				{
					fi = false;
				}
				thread->setPointer(pointer);
				thread->setFlag();
				thread->start();
				
				ui.actionrun->setIcon(QIcon(":/new/prefix1/stop.png"));
				ui.comboBox->setEnabled(false);
				ui.comboBox_2->setEnabled(false);
				ui.comboBox_2->setCurrentIndex(0);
			}
			else
			{
				index = !index;
			}
		}
		else
		{
			thread->resetFlag();
			thread->quit();
			thread->wait();
			ui.actionrun->setIcon(QIcon(":/new/prefix1/start.png"));
			ui.comboBox->setEnabled(true);
			ui.comboBox_2->setEnabled(true);
			pcap_close(pointer);
			pointer = nullptr;
		}
	});
	connect(ui.actionempty, &QAction::triggered, this, [=]() {
		ui.tableWidget->clearContents();
		ui.tableWidget->setRowCount(0);
		countNumber = 0;
		numberRow = -1;
		});
	connect(thread,&multhread::send, this, &sniffer::HandleMessage);
	connect(filt, &filter::send, this, &sniffer::HandlePair);

	ui.toolBar->setMovable(false);
	ui.tableWidget->setColumnCount(7);
	ui.tableWidget->verticalHeader()->setDefaultSectionSize(30);
	QStringList title = { "NO.","Time","Source","Destination","Protocal","Length","Info" };
	ui.tableWidget->setHorizontalHeaderLabels(title);

	ui.tableWidget->setColumnWidth(0, 50);
	ui.tableWidget->setColumnWidth(1, 100);
	ui.tableWidget->setColumnWidth(2, 300);
	ui.tableWidget->setColumnWidth(3, 300);
	ui.tableWidget->setColumnWidth(4, 100);
	ui.tableWidget->setColumnWidth(5, 100);
	ui.tableWidget->setColumnWidth(6, 700);

	ui.tableWidget->setShowGrid(false);
	ui.tableWidget->verticalHeader()->setVisible(false);
	ui.tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
	ui.treeWidget->setHeaderHidden(true);

}

sniffer::~sniffer()
{
	int dataSize = pData.size();
	for (int i = 0; i < dataSize; i++)
	{
		free((char*)(this->pData[i].pkt_content));
		this->pData[i].pkt_content = nullptr;
	}
	QVector<DataPackage>().swap(pData);
}

void sniffer::showNetworkCards()
{
	int i = 0;
	
	/* 获取本地网卡信息 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		ui.comboBox->addItem("error:" + QString(errbuf));
	}
	else
	{
		ui.comboBox->clear();
		ui.comboBox->addItem("please choose one card!");
		for (device = alldevs; device != nullptr; device = device->next)
		{
			/*
			QString device_name = device->name;
			device_name.replace("rpcap://\\Device\\","");
			QString device_des = device->description;
			device_des.replace("Network adapter", "");
			device_des.replace("on local host", "");
			QString item = device_name + device_des;
			*/
			ui.comboBox->addItem(device->description);
		}
	}
}

void sniffer::showProtocols()
{
	QStringList Protocols = { "Choose a protocol","ARP","TCP","UDP","ICMP","DNS" };
	for (int i = 0; i < Protocols.length(); i++)
	{
		ui.comboBox_2->addItem(Protocols[i]);
	}
}

void sniffer::on_comboBox_currentIndexChanged(int index)
{
	int i = 0;
	if (index != 0)
	{
		for (device = alldevs; i < index - 1; device = device->next ,i++);
	}
	return;
}

int sniffer::capture() 
{
	if (device)
	{
		pointer= pcap_open(device->name, MAXDATAFRAMES, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	}
	else 
	{
		return -1;
	}
	if (!pointer) 
	{
		pcap_freealldevs(alldevs);
		device = nullptr;
		return -1;
	}
	else
	{
		if (pcap_datalink(pointer) != DLT_EN10MB) return false;      // 必须是以太网协议
		statusBar()->showMessage(device->description);	
		return pointer != nullptr;
	}
}

void sniffer::on_comboBox_2_currentIndexChanged(QString pro)
{
	if (pro != "Choose a protocol")
	{
		ui.tableWidget->clearContents();
		ui.tableWidget->setRowCount(0);
		countNumber = 0;
		numberRow = -1;
		filt->quit();
		QVector<DataPackage>* pdata = &pData;
		if (fi == false)
		{
			filt->setPackages(pdata);
			fi = true;
		}
		select.clear();
		filt->setProtocol(pro);
		filt->run();
	}
}

void sniffer::HandleMessage(DataPackage data)
{
	ui.tableWidget->insertRow(countNumber);
	if (fi == false)
		this->pData.push_back(data);
	QString type = data.getPackageType();
	QColor color;
	if (type == "TCP")
		color = QColor(231, 230, 255);
	else if (type == "UDP")
		color = QColor(218, 238, 255);
	else if (type == "ARP")
		color = QColor(250, 240, 215);
	else if (type == "ICMP")
	 	color = QColor(252, 224, 255);
	else if (type == "DNS")
		color = QColor(218, 238, 255);
	
	ui.tableWidget->setItem(countNumber, 0, new QTableWidgetItem(QString::number(countNumber + 1)));
	ui.tableWidget->setItem(countNumber, 1, new QTableWidgetItem(data.getTimeStmp()));
	ui.tableWidget->setItem(countNumber, 2, new QTableWidgetItem(data.getSource()));
	ui.tableWidget->setItem(countNumber, 3, new QTableWidgetItem(data.getDestination()));
	ui.tableWidget->setItem(countNumber, 4, new QTableWidgetItem(data.getPackageType()));
	ui.tableWidget->setItem(countNumber, 5, new QTableWidgetItem(data.getDataLength()));
	ui.tableWidget->setItem(countNumber, 6, new QTableWidgetItem(data.getInfo()));
	for (int i = 0; i < 7; i++)
	{
		ui.tableWidget->item(countNumber, i)->setBackgroundColor(color);
	}
	countNumber++;
}

void sniffer::HandlePair(std::pair<int, int> selected)
{
	select.insert(selected);
	HandleMessage(pData[select[selected.first]]);
}

void sniffer::on_tableWidget_cellClicked(int  row, int column) 
{
	if (row == numberRow || row < 0)
	{
		return;
	}
	else
	{
		if (fi == true)
		{
			row = select[row];
		}
		ui.treeWidget->clear();
		numberRow = row;
		if(numberRow<0 /* || numberRow>countNumber*/)
		{ 
			return;
		}
		QString desMac = pData[numberRow].getDesMacAddr();
		QString srcMac = pData[numberRow].getSrcMacAddr();
		QString macType = pData[numberRow].getMacType();
		QString tree = "Ethernet,Src:" + srcMac + " Dst:" + desMac;
		QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
		ui.treeWidget->addTopLevelItem(item);
		item->addChild(new QTreeWidgetItem(QStringList() << "Source:" + srcMac));
		item->addChild(new QTreeWidgetItem(QStringList() << "Destination:" + desMac));
		item->addChild(new QTreeWidgetItem(QStringList() << "Type:" + macType));
		if (macType == "IPv4(0x0800)")
		{
			QString srcIp = pData[numberRow].getSrcIpAddr();
			QString desIp = pData[numberRow].getDesIpAddr();
			tree = "Internet Protocol Version 4, Src: " + srcIp + ", Dst:" + desIp;
			QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
			ui.treeWidget->addTopLevelItem(item);
			QString ipProtocol = pData[numberRow].getIpProtocol();
			item->addChildren(pData[numberRow].getIp());
			if (ipProtocol == "TCP(6)")
			{
				QString sPort = pData[numberRow].getTcpSrcPort();
				QString dPort = pData[numberRow].getTcpDesPort();
				tree = "Transmission Control Protocol, Src Port: " + sPort + ", Dst Port: " + dPort + ", ";
				QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
				ui.treeWidget->addTopLevelItem(item);
				QString seqNum = pData[numberRow].getTcpSeq();
				QString ackNum = pData[numberRow].getTcpAck();
				item->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + sPort));
				item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + dPort));
				item->addChild(new QTreeWidgetItem(QStringList() << seqNum));
				item->addChild(new QTreeWidgetItem(QStringList() << ackNum));
			}
			else if (ipProtocol == "UDP(17)")
			{
				QString sPort = pData[numberRow].getUdpSrcPort();
				QString dPort = pData[numberRow].getUdpDesPort();
				QString length = pData[numberRow].getUdpLength();
				tree = "User Datagram Protocol, Src Port: " + sPort + ", Dst Port: " + dPort + ", ";
				QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
				ui.treeWidget->addTopLevelItem(item);
				item->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + sPort));
				item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + dPort));
				item->addChild(new QTreeWidgetItem(QStringList() << "Length: " + length));
				if (sPort == "53" || dPort == "53")
				{
					QString qr = pData[numberRow].getDnsFlagsQR();
					tree = "Domain Name System";
					if (qr == "0 Message is a query")
						tree += " (query)";
					else if (qr == "1 Message is a response")
						tree += " (response)";
					QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
					ui.treeWidget->addTopLevelItem(item);
					item->addChildren(pData[numberRow].getDns());
				}
			}
			else if (ipProtocol == "ICMP(1)")
			{
				tree = "Internet Control Message Protocol";
				QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
				ui.treeWidget->addTopLevelItem(item);
				item->addChildren(pData[numberRow].getIcmp());
			}
		}
		else if (macType == "ARP(0x0806)")
		{
			QString Op = pData[numberRow].getArpOp();
			if (Op == "request(1)")
			{
				tree = "Address Resolution Protocol (request)";
			}
			else if (Op == "reply(2)")
			{
				tree = "Address Resolution Protocol (reply)";
			}
			else
			{
				tree = "Address Resolution Protocol";
			}
			QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
			ui.treeWidget->addTopLevelItem(item);
			item->addChildren(pData[numberRow].getArp());
		}
	}
}
