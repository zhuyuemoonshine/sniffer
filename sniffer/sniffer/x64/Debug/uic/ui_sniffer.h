/********************************************************************************
** Form generated from reading UI file 'sniffer.ui'
**
** Created by: Qt User Interface Compiler version 5.14.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SNIFFER_H
#define UI_SNIFFER_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_snifferClass
{
public:
    QAction *actionrun;
    QAction *actionempty;
    QWidget *centralWidget;
    QVBoxLayout *verticalLayout_2;
    QWidget *widget_2;
    QVBoxLayout *verticalLayout;
    QWidget *widget;
    QHBoxLayout *horizontalLayout;
    QComboBox *comboBox;
    QSpacerItem *horizontalSpacer;
    QComboBox *comboBox_2;
    QSplitter *splitter;
    QTableWidget *tableWidget;
    QTreeWidget *treeWidget;
    QStatusBar *statusBar;
    QMenuBar *menuBar;
    QMenu *menuproject;
    QMenu *menurun;
    QToolBar *toolBar;

    void setupUi(QMainWindow *snifferClass)
    {
        if (snifferClass->objectName().isEmpty())
            snifferClass->setObjectName(QString::fromUtf8("snifferClass"));
        snifferClass->resize(1134, 698);
        actionrun = new QAction(snifferClass);
        actionrun->setObjectName(QString::fromUtf8("actionrun"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/new/prefix1/start.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionrun->setIcon(icon);
        actionempty = new QAction(snifferClass);
        actionempty->setObjectName(QString::fromUtf8("actionempty"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/new/prefix1/empty.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionempty->setIcon(icon1);
        centralWidget = new QWidget(snifferClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        verticalLayout_2 = new QVBoxLayout(centralWidget);
        verticalLayout_2->setSpacing(6);
        verticalLayout_2->setContentsMargins(11, 11, 11, 11);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        widget_2 = new QWidget(centralWidget);
        widget_2->setObjectName(QString::fromUtf8("widget_2"));
        verticalLayout = new QVBoxLayout(widget_2);
        verticalLayout->setSpacing(6);
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        widget = new QWidget(widget_2);
        widget->setObjectName(QString::fromUtf8("widget"));
        horizontalLayout = new QHBoxLayout(widget);
        horizontalLayout->setSpacing(6);
        horizontalLayout->setContentsMargins(11, 11, 11, 11);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        comboBox = new QComboBox(widget);
        comboBox->setObjectName(QString::fromUtf8("comboBox"));
        comboBox->setMinimumSize(QSize(350, 0));

        horizontalLayout->addWidget(comboBox);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        comboBox_2 = new QComboBox(widget);
        comboBox_2->setObjectName(QString::fromUtf8("comboBox_2"));
        comboBox_2->setMinimumSize(QSize(200, 0));

        horizontalLayout->addWidget(comboBox_2);


        verticalLayout->addWidget(widget);

        splitter = new QSplitter(widget_2);
        splitter->setObjectName(QString::fromUtf8("splitter"));
        splitter->setOrientation(Qt::Vertical);
        tableWidget = new QTableWidget(splitter);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        splitter->addWidget(tableWidget);
        treeWidget = new QTreeWidget(splitter);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName(QString::fromUtf8("treeWidget"));
        splitter->addWidget(treeWidget);

        verticalLayout->addWidget(splitter);


        verticalLayout_2->addWidget(widget_2);

        snifferClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(snifferClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        snifferClass->setStatusBar(statusBar);
        menuBar = new QMenuBar(snifferClass);
        menuBar->setObjectName(QString::fromUtf8("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 1134, 26));
        menuproject = new QMenu(menuBar);
        menuproject->setObjectName(QString::fromUtf8("menuproject"));
        menurun = new QMenu(menuBar);
        menurun->setObjectName(QString::fromUtf8("menurun"));
        snifferClass->setMenuBar(menuBar);
        toolBar = new QToolBar(snifferClass);
        toolBar->setObjectName(QString::fromUtf8("toolBar"));
        snifferClass->addToolBar(Qt::TopToolBarArea, toolBar);

        menuBar->addAction(menuproject->menuAction());
        menuBar->addAction(menurun->menuAction());
        menurun->addAction(actionrun);
        menurun->addAction(actionempty);

        retranslateUi(snifferClass);

        QMetaObject::connectSlotsByName(snifferClass);
    } // setupUi

    void retranslateUi(QMainWindow *snifferClass)
    {
        snifferClass->setWindowTitle(QCoreApplication::translate("snifferClass", "sniffer", nullptr));
        actionrun->setText(QCoreApplication::translate("snifferClass", "runandstop", nullptr));
        actionempty->setText(QCoreApplication::translate("snifferClass", "empty", nullptr));
        menuproject->setTitle(QCoreApplication::translate("snifferClass", "project", nullptr));
        menurun->setTitle(QCoreApplication::translate("snifferClass", "run", nullptr));
        toolBar->setWindowTitle(QCoreApplication::translate("snifferClass", "toolBar", nullptr));
    } // retranslateUi

};

namespace Ui {
    class snifferClass: public Ui_snifferClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_SNIFFER_H
