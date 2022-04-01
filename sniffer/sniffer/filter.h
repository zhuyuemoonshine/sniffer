#pragma once
#include "qthread.h"
#include "DataPackage.h"
#include <map>

class filter:public QThread
{
	Q_OBJECT
public:
	void setPackages(QVector<DataPackage>* pData);
	void setProtocol(QString protocol);
	void run() override;


signals:
	void send(std::pair<int,int> selected);

private:
	QVector<DataPackage>* backUp;
	QString pro;
};

