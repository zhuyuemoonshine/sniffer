#include "filter.h"



void filter::setPackages(QVector<DataPackage>* pData)
{
	backUp = pData;
}

void filter::setProtocol(QString protocol)
{
	pro = protocol;
}

void filter::run()
{
	int j = 0;
	for (int i = 0; i < backUp->length(); i++)
	{
		QString type = backUp[0][i].getPackageType();//getPackageType();
		if (type == pro)
		{
			emit send(std::pair<int, int>(j, i));
			j++;
		}
	}
}