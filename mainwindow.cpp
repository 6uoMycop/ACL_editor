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

QString MainWindow::sidToUsername(PSID pSid)
{
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(
        NULL,           // local computer
        pSid,
        AcctName,
        (LPDWORD)&dwAcctName,
        DomainName,
        (LPDWORD)&dwDomainName,
        &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwAcctName * sizeof(WCHAR));
    if (AcctName == NULL)
    {
        printf("GlobalAlloc error = %lu\n", GetLastError());
        return QString("<error>");
    }

    DomainName = (LPTSTR)GlobalAlloc(
        GMEM_FIXED,
        dwDomainName * sizeof(WCHAR));
    if (DomainName == NULL)
    {
        printf("GlobalAlloc error = %lu\n", GetLastError());
        GlobalFree(AcctName);
        return QString("<error>");
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
        NULL,                   // name of local or remote computer
        pSid,                   // security identifier
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

QString MainWindow::getOwner()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
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

    return sidToUsername(pSidOwner);
}


int MainWindow::showACL()
{
    PACL oldDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD err;
    PEXPLICIT_ACCESS entryList;
    ULONG entryCount;
    QString items[6] = { "" };
    int maxLines;

    err = GetNamedSecurityInfo(
        fileName.toStdWString().data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        &oldDACL,
        NULL,
        &pSD
    );
    if (ERROR_SUCCESS != err)
    {
        return 1;
    }

    err = GetExplicitEntriesFromAcl(
        oldDACL,
        &entryCount,
        &entryList
    );
    if (ERROR_SUCCESS != err)
    {
        LocalFree(oldDACL);
        return 1;
    }

    for (unsigned int i = 0; i < entryCount; i++)
    {
        maxLines = 1;

        if (entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_SID)
        {
            items[0] += sidToUsername(entryList[i].Trustee.ptstrName);
        }
        else if (entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME)
        {
            items[0] += QString::fromWCharArray(entryList[i].Trustee.ptstrName);
        }
        else // TRUSTEE_IS_OBJECTS_AND_NAME || TRUSTEE_IS_OBJECTS_AND_SID
        {
            printf("TODO TRUSTEE_IS_OBJECTS_AND_NAME || TRUSTEE_IS_OBJECTS_AND_SID");
            items[0] += "<TODO>";
        }


        // Specific
        if ((entryList[i].grfAccessPermissions & 0x01) == 0x01) // FILE_READ_DATA || FILE_LIST_DIRECTORY
        {
            items[2] += QString::fromWCharArray(L"0x01\n");
        }
        if ((entryList[i].grfAccessPermissions & 0x02) == 0x02) // FILE_WRITE_DATA || FILE_ADD_FILE
        {
            items[2] += QString::fromWCharArray(L"0x02\n");
        }
        if ((entryList[i].grfAccessPermissions & 0x04) == 0x04) // FILE_APPEND_DATA || FILE_ADD_SUBDIRECTORY
        {
            items[2] += QString::fromWCharArray(L"0x04\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_READ_EA) == FILE_READ_EA)
        {
            items[2] += QString::fromWCharArray(L"FILE_READ_EA\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_WRITE_EA) == FILE_WRITE_EA)
        {
            items[2] += QString::fromWCharArray(L"FILE_WRITE_EA\n");
        }
        if ((entryList[i].grfAccessPermissions & 0x20) == 0x20) // FILE_EXECUTE || FILE_TRAVERSE
        {
            items[2] += QString::fromWCharArray(L"0x20\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
        {
            items[2] += QString::fromWCharArray(L"FILE_DELETE_CHILD\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
        {
            items[2] += QString::fromWCharArray(L"FILE_READ_ATTRIBUTES\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
        {
            items[2] += QString::fromWCharArray(L"FILE_WRITE_ATTRIBUTES\n");
        }
        items[2] = items[2].left(items[2].lastIndexOf(QChar('\n')));

        // Standard
        if ((entryList[i].grfAccessPermissions & DELETE) == DELETE)
        {
            items[3] += QString::fromWCharArray(L"DELETE\n");
        }
        if ((entryList[i].grfAccessPermissions & READ_CONTROL) == READ_CONTROL)
        {
            items[3] += QString::fromWCharArray(L"READ_CONTROL\n");
        }
        if ((entryList[i].grfAccessPermissions & WRITE_DAC) == WRITE_DAC)
        {
            items[3] += QString::fromWCharArray(L"WRITE_DAC\n");
        }
        if ((entryList[i].grfAccessPermissions & WRITE_OWNER) == WRITE_OWNER)
        {
            items[3] += QString::fromWCharArray(L"WRITE_OWNER\n");
        }
        if ((entryList[i].grfAccessPermissions & SYNCHRONIZE) == SYNCHRONIZE)
        {
            items[3] += QString::fromWCharArray(L"SYNCHRONIZE\n");
        }
        items[3] = items[3].left(items[3].lastIndexOf(QChar('\n')));

        // Other
        if ((entryList[i].grfAccessPermissions & ACCESS_SYSTEM_SECURITY) == ACCESS_SYSTEM_SECURITY)
        {
            items[5] += QString::fromWCharArray(L"ACCESS_SYSTEM_SECURITY\n");
        }
        if ((entryList[i].grfAccessPermissions & MAXIMUM_ALLOWED) == MAXIMUM_ALLOWED)
        {
            items[5] += QString::fromWCharArray(L"MAXIMUM_ALLOWED\n");
        }
        items[5] = items[5].left(items[5].lastIndexOf(QChar('\n')));

        // Generic
        if ((entryList[i].grfAccessPermissions & GENERIC_ALL) == GENERIC_ALL)
        {
            items[4] += QString::fromWCharArray(L"GENERIC_ALL\n");
        }
        if ((entryList[i].grfAccessPermissions & GENERIC_EXECUTE) == GENERIC_EXECUTE)
        {
            items[4] += QString::fromWCharArray(L"GENERIC_EXECUTE\n");
        }
        if ((entryList[i].grfAccessPermissions & GENERIC_WRITE) == GENERIC_WRITE)
        {
            items[4] += QString::fromWCharArray(L"GENERIC_WRITE\n");
        }
        if ((entryList[i].grfAccessPermissions & GENERIC_READ) == GENERIC_READ)
        {
            items[4] += QString::fromWCharArray(L"GENERIC_READ\n");
        }
        items[4] = items[4].left(items[4].lastIndexOf(QChar('\n')));

        //AccessMode
        (entryList[i].grfAccessMode == GRANT_ACCESS) ?  items[1] += QString::fromWCharArray(L"GRANT_ACCESS") :
        (entryList[i].grfAccessMode == SET_ACCESS) ?    items[1] += QString::fromWCharArray(L"SET_ACCESS") :
        (entryList[i].grfAccessMode == DENY_ACCESS) ?   items[1] += QString::fromWCharArray(L"DENY_ACCESS") :
        (entryList[i].grfAccessMode == REVOKE_ACCESS) ? items[1] += QString::fromWCharArray(L"REVOKE_ACCESS") :
                                                        items[1] += QString::fromWCharArray(L"");

        ui->tableWidget_ACL->insertRow(ui->tableWidget_ACL->rowCount());
        for (int ind = 0; ind < 6; ind++)
        {
            ui->tableWidget_ACL->setItem(
                        ui->tableWidget_ACL->rowCount()-1,
                        ind,
                        new QTableWidgetItem(items[ind]));
            if(maxLines < items[ind].count(QLatin1Char('\n')))
            {
                maxLines = items[ind].count(QLatin1Char('\n'));
            }
        }

        // TODO: set row height

    }

    if(entryList)
    {
        LocalFree(entryList);
    }
    LocalFree(pSD);
    return 0;
}

void MainWindow::on_pushButton_Open_clicked()
{
    fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "", tr("Any File (*.*)"));
    ui->lineEdit_FileName->setText(fileName);
    ui->lineEdit_Owner->setText(getOwner());
    showACL();
}
