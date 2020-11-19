#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::showOwner()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Get the handle of the file object.
    hFile = CreateFile(
        fileName.toStdWString().data(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("CreateFile error = %lu\n", GetLastError());
        return QString("<error>");
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
        hFile,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pSidOwner,
        NULL,
        NULL,
        NULL,
        &pSD);

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS)
    {
        printf("GetSecurityInfo error = %lu\n", GetLastError());
        return QString("<error>");
    }

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(
        NULL,           // local computer
        pSidOwner,
        AcctName,
        (LPDWORD)&dwAcctName,
        DomainName,
        (LPDWORD)&dwDomainName,
        &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwAcctName);
    if (AcctName == NULL)
    {
        printf("GlobalAlloc error = %lu\n", GetLastError());
        return QString("<error>");
    }

    DomainName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwDomainName);
    if (DomainName == NULL)
    {
        printf("GlobalAlloc error = %lu\n", GetLastError());
        GlobalFree(AcctName);
        return QString("<error>");
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
        NULL,                   // name of local or remote computer
        pSidOwner,              // security identifier
        AcctName,               // account name buffer
        (LPDWORD)&dwAcctName,   // size of account name buffer
        DomainName,             // domain name
        (LPDWORD)&dwDomainName, // size of domain name buffer
        &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool)
    {
        //printf("Owner: %s\n", AcctName);
        QString res = QString::fromWCharArray(AcctName);
        GlobalFree(AcctName);
        GlobalFree(DomainName);
        return res;
    }
    else
    {
        printf("Error in LookupAccountSid. GLE=%lu\n", GetLastError());
        GlobalFree(AcctName);
        GlobalFree(DomainName);
        return QString("<error>");
    }
}


void MainWindow::on_pushButton_Open_clicked()
{
    fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "", tr("Any File (*.*)"));
    ui->lineEdit_FileName->setText(fileName);
    ui->lineEdit_Owner->setText(showOwner());
}
