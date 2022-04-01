#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_sniffer.h"
#include "pcap.h"
#include "DataPackage.h"
#include <QVector>
#include "filter.h"
#include <map>

class sniffer : public QMainWindow
{
    Q_OBJECT

public:
    sniffer(QWidget *parent = Q_NULLPTR);
    ~sniffer();
    void showNetworkCards();
    void showProtocols();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int  row, int column);
    void on_comboBox_2_currentIndexChanged(QString pro);
    

public slots:
    void HandleMessage(DataPackage data);
    void HandlePair(std::pair<int, int> selected);

private:
    Ui::snifferClass ui;
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* pointer;
    QVector<DataPackage>pData;
    QVector<DataPackage>showData;
    int countNumber;
    char errbuf[PCAP_ERRBUF_SIZE];
    int numberRow;
    filter* filt;
    bool fi;
    std::map<int, int> select;

#define  MAXDATAFRAMES 1518
};
