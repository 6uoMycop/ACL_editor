#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QTableWidget>
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
    void on_pushButton_OpenDirectory_clicked();

    void on_pushButton_OpenFile_clicked();

    void on_pushButton_New_clicked();

    void on_pushButton_Save_clicked();

    void on_tableWidget_ACL_itemDoubleClicked(QTableWidgetItem *item);

    void on_pushButton_Cancel_clicked();

    void on_pushButton_CheckName_clicked();

    void on_pushButton_Delete_clicked();

    void on_tableWidget_ACL_itemClicked(QTableWidgetItem *item);

private:
    Ui::MainWindow* ui;

    QString              fileName;
    bool                 isFile;
    bool                 isAbleToEdit;
    bool                 fIsElevated;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PEXPLICIT_ACCESS     entryList;
    PACL                 oldDACL = NULL;
    ULONG                entryCount;
    int                  selectedRow;

    bool                 checkIfProcessElevated();
    BOOL                 SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
    void                 checkOwner(QString owner);
    QString              sidToUsername(PSID pSid);
    PSID                 usernameToSid(QString username);
    QString              getOwner();
    int                  showACL();
    bool                 setACL(PACL newDACL);
    bool                 saveACE();
    bool                 deleteSelectedAce(int index);
    void                 cleanupGlobals();
    void                 revertEditorFormat();

};
#endif // MAINWINDOW_H
