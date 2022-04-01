#include "sniffer.h"
#include "dev.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    sniffer w;
    w.show();
    return a.exec();
}
