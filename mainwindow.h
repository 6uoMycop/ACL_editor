#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <lmcons.h>
#include <string.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


private slots:
    void on_pushButton_Open_clicked();

private:
    Ui::MainWindow *ui;

    QString fileName;
    ACL ACE;

    QString sidToUsername(PSID pSid);
    QString getOwner();
    int showACL();

};
#endif // MAINWINDOW_H
