#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget_ACL->resizeColumnsToContents();
    ui->widget_Container->setEnabled(false);
    ui->pushButton_Save->setEnabled(false);
    ui->pushButton_Cancel->setEnabled(false);
    ui->pushButton_New->setEnabled(false);
    ui->pushButton_Delete->setEnabled(false);

    oldDACL = NULL;
    entryList = NULL;
}

MainWindow::~MainWindow()
{
    cleanupGlobals();
    delete ui;
}

BOOL MainWindow::SetPrivilege(
    HANDLE hToken,              // access token handle
    LPCTSTR lpszPrivilege,   // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    // Used by local system to identify the privilege
    LUID luid;

    if(!LookupPrivilegeValue(
            NULL,                // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid))              // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %lu\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if(bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    // Enable the privilege or disable all privileges.
    if(!AdjustTokenPrivileges(
                hToken,
                FALSE,
                &tp,
                sizeof(TOKEN_PRIVILEGES),
                (PTOKEN_PRIVILEGES) NULL,
                (PDWORD) NULL))
    {
        printf("AdjustTokenPrivileges error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
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

// LocalFree return value!!!
PSID MainWindow::usernameToSid(QString username)
{
    PSID pSid = NULL;
    PTCHAR pDomain;
    DWORD dwSidSize = 0, dwDomainSize = 0;
    SID_NAME_USE use;
    bool ret = true;
    DWORD err = ERROR_SUCCESS;

    ret = LookupAccountName(
                NULL,
                username.toStdWString().data(),
                pSid,
                &dwSidSize,
                NULL,
                &dwDomainSize,
                &use);
    if(!ret)
    {
        err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER)
        {
            return NULL;
        }
    }

    pSid = (PSID)LocalAlloc(LMEM_FIXED, dwSidSize);
    if (pSid == NULL)
    {
        return NULL;
    }

    pDomain = (PTCHAR)LocalAlloc(LMEM_FIXED, dwDomainSize * sizeof(TCHAR));
    if (pDomain == NULL)
    {
        LocalFree(pSid);
        return NULL;
    }

    ret = LookupAccountName(
                NULL,
                username.toStdWString().data(),
                pSid,
                &dwSidSize,
                pDomain,
                &dwDomainSize,
                &use);
    if(!ret)
    {
        LocalFree(pSid);
        LocalFree(pDomain);
        return NULL;
    }

    LocalFree(pDomain);
    return pSid;
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
    DWORD err;
    int genCntrAll, genCntrR, genCntrW, genCntrE;

    ui->tableWidget_ACL->clearContents();
    ui->tableWidget_ACL->setRowCount(0);
    entryCount = 0;

    err = GetNamedSecurityInfo(
                fileName.toStdWString().data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                NULL,
                NULL,
                &oldDACL,
                NULL,
                &pSD);
    if (ERROR_SUCCESS != err)
    {
        return 1;
    }

    err = GetExplicitEntriesFromAcl(
                oldDACL,
                &entryCount,
                &entryList);
    if (ERROR_SUCCESS != err)
    {
        //LocalFree(oldDACL);
        LocalFree(pSD); /// test
        pSD = NULL;     /// test
        oldDACL = NULL;
        return 1;
    }

    for (unsigned int i = 0; i < entryCount; i++)
    {
        QString items[6] = { "" };
        genCntrAll = 0;
        genCntrR = 0;
        genCntrW = 0;
        genCntrE = 0;

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
            genCntrAll++;
            genCntrR++;
            if(isFile)
            {
                items[2] += QString::fromWCharArray(L"FILE_READ_DATA\n");
            }
            else
            {
                items[2] += QString::fromWCharArray(L"FILE_LIST_DIRECTORY\n");
            }
        }
        if ((entryList[i].grfAccessPermissions & 0x02) == 0x02) // FILE_WRITE_DATA || FILE_ADD_FILE
        {
            genCntrAll++;
            genCntrW++;
            if(isFile)
            {
                items[2] += QString::fromWCharArray(L"FILE_WRITE_DATA\n");
            }
            else
            {
                items[2] += QString::fromWCharArray(L"FILE_ADD_FILE\n");
            }
        }
        if ((entryList[i].grfAccessPermissions & 0x04) == 0x04) // FILE_APPEND_DATA || FILE_ADD_SUBDIRECTORY
        {
            genCntrAll++;
            genCntrW++;
            if(isFile)
            {
                items[2] += QString::fromWCharArray(L"FILE_APPEND_DATA\n");
            }
            else
            {
                items[2] += QString::fromWCharArray(L"FILE_ADD_SUBDIRECTORY\n");
            }
        }
        if ((entryList[i].grfAccessPermissions & FILE_READ_EA) == FILE_READ_EA)
        {
            genCntrAll++;
            genCntrR++;
            items[2] += QString::fromWCharArray(L"FILE_READ_EA\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_WRITE_EA) == FILE_WRITE_EA)
        {
            genCntrAll++;
            genCntrW++;
            items[2] += QString::fromWCharArray(L"FILE_WRITE_EA\n");
        }
        if ((entryList[i].grfAccessPermissions & 0x20) == 0x20) // FILE_EXECUTE || FILE_TRAVERSE
        {
            genCntrAll++;
            genCntrE++;
            if(isFile)
            {
                items[2] += QString::fromWCharArray(L"FILE_EXECUTE\n");
            }
            else
            {
                items[2] += QString::fromWCharArray(L"FILE_TRAVERSE\n");
            }
        }
        if ((entryList[i].grfAccessPermissions & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
        {
            genCntrAll++;
            items[2] += QString::fromWCharArray(L"FILE_DELETE_CHILD\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
        {
            genCntrAll++;
            genCntrE++;
            genCntrR++;
            items[2] += QString::fromWCharArray(L"FILE_READ_ATTRIBUTES\n");
        }
        if ((entryList[i].grfAccessPermissions & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
        {
            genCntrAll++;
            genCntrW++;
            items[2] += QString::fromWCharArray(L"FILE_WRITE_ATTRIBUTES\n");
        }
        items[2] = items[2].left(items[2].lastIndexOf(QChar('\n')));

        // Standard
        if ((entryList[i].grfAccessPermissions & DELETE) == DELETE)
        {
            genCntrAll++;
            items[3] += QString::fromWCharArray(L"DELETE\n");
        }
        if ((entryList[i].grfAccessPermissions & READ_CONTROL) == READ_CONTROL)
        {
            genCntrAll++;
            genCntrR++;
            genCntrW++;
            genCntrE++;
            items[3] += QString::fromWCharArray(L"READ_CONTROL\n");
        }
        if ((entryList[i].grfAccessPermissions & WRITE_DAC) == WRITE_DAC)
        {
            genCntrAll++;
            items[3] += QString::fromWCharArray(L"WRITE_DAC\n");
        }
        if ((entryList[i].grfAccessPermissions & WRITE_OWNER) == WRITE_OWNER)
        {
            genCntrAll++;
            items[3] += QString::fromWCharArray(L"WRITE_OWNER\n");
        }
        if ((entryList[i].grfAccessPermissions & SYNCHRONIZE) == SYNCHRONIZE)
        {
            genCntrAll++;
            genCntrR++;
            genCntrW++;
            genCntrE++;
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
        // Generic
        if(genCntrAll == 14)
        {
            items[4] += QString::fromWCharArray(L"(GENERIC_ALL)");
        }
        else
        {
            if(genCntrR == 5)
            {
                items[4] += QString::fromWCharArray(L"(GENERIC_READ)");
            }
            else if(genCntrW == 6)
            {
                items[4] += QString::fromWCharArray(L"(GENERIC_WRITE)");
            }
            else if(genCntrE == 4)
            {
                items[4] += QString::fromWCharArray(L"(GENERIC_EXECUTE)");
            }
        }

        //AccessMode
        (entryList[i].grfAccessMode == GRANT_ACCESS) ?  items[1] += QString::fromWCharArray(L"GRANT_ACCESS") :
        (entryList[i].grfAccessMode == SET_ACCESS) ?    items[1] += QString::fromWCharArray(L"SET_ACCESS") :
        (entryList[i].grfAccessMode == DENY_ACCESS) ?   items[1] += QString::fromWCharArray(L"DENY_ACCESS") :
        (entryList[i].grfAccessMode == REVOKE_ACCESS) ? items[1] += QString::fromWCharArray(L"REVOKE_ACCESS") :
                                                        items[1] += QString::fromWCharArray(L"");

        ui->tableWidget_ACL->insertRow(ui->tableWidget_ACL->rowCount());
        for (int ind = 0; ind < 6; ind++)
        {
            QTableWidgetItem* tmp = new QTableWidgetItem(items[ind]);
            tmp->setTextAlignment(Qt::AlignTop | Qt::AlignLeft);
            ui->tableWidget_ACL->setItem(
                        ui->tableWidget_ACL->rowCount() - 1,
                        ind,
                        tmp);
        }
    }


    ui->tableWidget_ACL->resizeColumnsToContents();
    ui->tableWidget_ACL->resizeRowsToContents();

    return 0;
}

bool MainWindow::setACL(PACL newDACL)
{
    DWORD err;

    // Attach new ACL to the file

    // PROTECTED_DACL_SECURITY_INFORMATION causes the function to NOT
    // inherit its parent's ACL. I believe this is what we want.
    err = SetNamedSecurityInfo(
                (LPWSTR)fileName.toStdWString().data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL,
                NULL,
                newDACL,
                NULL);

    if (err == ERROR_ACCESS_DENIED)
    {
        // set the SE_SECURITY_NAME privilege and try again.
        HANDLE hToken = NULL;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            // Enable the SE_SECURITY_NAME privilege.
            if (SetPrivilege(hToken, SE_SECURITY_NAME, TRUE))
            {
                err = SetNamedSecurityInfo(
                            (LPWSTR)fileName.toStdWString().data(),
                            SE_FILE_OBJECT,
                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                            NULL,
                            NULL,
                            newDACL,
                            NULL);
            }
            CloseHandle(hToken);
        }
    }

    if (err != ERROR_SUCCESS)
    {
        return false;
    }

    return true;
}

bool MainWindow::saveACE()
{
    ACCESS_MASK     accessMask = 0;
    ACCESS_MODE     accessMode = NOT_USED_ACCESS;
    PSID            pSid       = NULL;
    EXPLICIT_ACCESS ea;
    PACL            newDACL    = NULL;
    bool            retval     = false;
    DWORD           err        = 0;

    //
    // ACCESS_MASK
    //

    // specific
    if(ui->checkBox_FILE_READ_DATA->isChecked())
    {
        accessMask ^= FILE_READ_DATA;
    }
    if(ui->checkBox_FILE_LIST_DIRECTORY->isChecked())
    {
        accessMask ^= FILE_LIST_DIRECTORY;
    }
    if(ui->checkBox_FILE_WRITE_DATA->isChecked())
    {
        accessMask ^= FILE_WRITE_DATA;
    }
    if(ui->checkBox_FILE_ADD_FILE->isChecked())
    {
        accessMask ^= FILE_ADD_FILE;
    }
    if(ui->checkBox_FILE_APPEND_DATA->isChecked())
    {
        accessMask ^= FILE_APPEND_DATA;
    }
    if(ui->checkBox_FILE_ADD_SUBDIRECTORY->isChecked())
    {
        accessMask ^= FILE_ADD_SUBDIRECTORY;
    }
    if(ui->checkBox_FILE_READ_EA->isChecked())
    {
        accessMask ^= FILE_READ_EA;
    }
    if(ui->checkBox_FILE_WRITE_EA->isChecked())
    {
        accessMask ^= FILE_WRITE_EA;
    }
    if(ui->checkBox_FILE_EXECUTE->isChecked())
    {
        accessMask ^= FILE_EXECUTE;
    }
    if(ui->checkBox_FILE_TRAVERSE->isChecked())
    {
        accessMask ^= FILE_TRAVERSE;
    }
    if(ui->checkBox_FILE_DELETE_CHILD->isChecked())
    {
        accessMask ^= FILE_DELETE_CHILD;
    }
    if(ui->checkBox_FILE_READ_ATTRIBUTES->isChecked())
    {
        accessMask ^= FILE_READ_ATTRIBUTES;
    }
    if(ui->checkBox_FILE_WRITE_ATTRIBUTES->isChecked())
    {
        accessMask ^= FILE_WRITE_ATTRIBUTES;
    }

    // standard
    if(ui->checkBox_DELETE->isChecked())
    {
        accessMask ^= DELETE;
    }
    if(ui->checkBox_READ_CONTROL->isChecked())
    {
        accessMask ^= READ_CONTROL;
    }
    if(ui->checkBox_WRITE_DAC->isChecked())
    {
        accessMask ^= WRITE_DAC;
    }
    if(ui->checkBox_WRITE_OWNER->isChecked())
    {
        accessMask ^= WRITE_OWNER;
    }
    if(ui->checkBox_SYNCHRONIZE->isChecked())
    {
        accessMask ^= SYNCHRONIZE;
    }

    // other
    if(ui->checkBox_ACCESS_SYSTEM_SECURITY->isChecked())
    {
        accessMask ^= ACCESS_SYSTEM_SECURITY;
    }
    if(ui->checkBox_MAXIMUM_ALLOWED->isChecked())
    {
        accessMask ^= MAXIMUM_ALLOWED;
    }

    // generic
    if(ui->checkBox_GENERIC_ALL->isChecked())
    {
        accessMask ^= GENERIC_ALL;
    }
    if(ui->checkBox_GENERIC_EXECUTE->isChecked())
    {
        accessMask ^= GENERIC_EXECUTE;
    }
    if(ui->checkBox_GENERIC_WRITE->isChecked())
    {
        accessMask ^= GENERIC_WRITE;
    }
    if(ui->checkBox_GENERIC_READ->isChecked())
    {
        accessMask ^= GENERIC_READ;
    }

    //
    // Access Mode
    //

    if(!ui->comboBox_AccessMode->currentIndex())
    {
        return false;
    }

    accessMode =
            (ui->comboBox_AccessMode->currentIndex() == 1) ? GRANT_ACCESS :
            (ui->comboBox_AccessMode->currentIndex() == 2) ? SET_ACCESS :
            (ui->comboBox_AccessMode->currentIndex() == 3) ? DENY_ACCESS :
            (ui->comboBox_AccessMode->currentIndex() == 4) ? REVOKE_ACCESS :
                                                             NOT_USED_ACCESS;

    //
    // Trustee
    //

    if(!ui->lineEdit_SID->text().length())
    {
        return false;
    }

    ConvertStringSidToSid(ui->lineEdit_SID->text().toStdWString().data(), &pSid);


    //
    // Fill in ACE
    //

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions             = accessMask;
    ea.grfAccessMode                    = accessMode;
    ea.grfInheritance                   = NO_INHERITANCE; // TODO: check this
    ea.Trustee.pMultipleTrustee         = NULL;
    ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    ea.Trustee.TrusteeForm              = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType              = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName                = (LPWCH)pSid;

    //
    // Check if ACE exists
    //

    for (unsigned int i = 0; i < entryCount; i++)
    {
        if((entryList[i].grfAccessPermissions == ea.grfAccessPermissions) &&
           (entryList[i].grfAccessMode        == ea.grfAccessMode))
        {
            if(entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_SID)
            {
                if(memcmp(entryList[i].Trustee.ptstrName, ea.Trustee.ptstrName, sizeof(SID)) == 0)
                {
                    LocalFree(pSid);
                    return false;
                }
            }
            else if(entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME)
            {

                if(sidToUsername(pSid) == QString::fromStdWString(entryList[i].Trustee.ptstrName))
                {
                    LocalFree(pSid);
                    return false;
                }
            }
            else
            {
                LocalFree(pSid);
                printf("TODO");
                return false;
            }
        }
    }

    //LocalFree(pSid);


    //
    // Assign ACE
    //

    // if we are editing ACE delete this ACE first
    if (!(ui->tableWidget_ACL->item(selectedRow, 0)->text() == QString("UNSAVED")))
    {
        if(!DeleteAce(oldDACL, selectedRow))
        {
            cleanupGlobals();
            LocalFree(pSid);
            return false;
        }
    }

    // create the new ACL with the new ACEs
    err = SetEntriesInAcl(
                1,
                &ea,
                oldDACL,
                &newDACL);

    if(ERROR_SUCCESS != err)
    {
        cleanupGlobals();
        LocalFree(pSid);
        return false;
    }

    retval = setACL(newDACL);

    // clean up our memory.
    LocalFree(newDACL);
    cleanupGlobals();
    if(!retval)
    {
        LocalFree(pSid);
    }

    return retval;
}

bool MainWindow::deleteSelectedAce(int index)
{
    if(!DeleteAce(oldDACL, index))
    {
        return false;
    }

    setACL(oldDACL);

    return true;
}

void MainWindow::cleanupGlobals()
{
    if(pSD)
    {
        LocalFree(pSD);
        pSD = NULL;
        oldDACL = NULL;
    }
    if(entryList != NULL)
    {
        LocalFree(entryList);
        entryList = NULL;
    }
    entryCount = 0;
}

void MainWindow::on_pushButton_OpenDirectory_clicked()
{
    cleanupGlobals();
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::DirectoryOnly);
    fileName = dialog.getExistingDirectory(this, "Open directory");
    if(!fileName.length())
    {
        return;
    }
    ui->pushButton_New->setEnabled(true);
    isFile = false;
    ui->lineEdit_FileName->setText(fileName);
    ui->lineEdit_Owner->setText(getOwner());
    showACL();
}

void MainWindow::on_pushButton_OpenFile_clicked()
{
    cleanupGlobals();
    fileName = QFileDialog::getOpenFileName(this, "Open file");
    if(!fileName.length())
    {
        return;
    }
    ui->pushButton_New->setEnabled(true);
    isFile = true;
    ui->lineEdit_FileName->setText(fileName);
    ui->lineEdit_Owner->setText(getOwner());
    showACL();
}

void MainWindow::on_pushButton_New_clicked()
{
    ui->pushButton_New->setEnabled(false);

    QString items[6] = {
        "UNSAVED",
        "",
        "EDIT",
        "THIS",
        "ROW",
        "FIRST"
    };
    ui->tableWidget_ACL->insertRow(ui->tableWidget_ACL->rowCount());
    for (int ind = 0; ind < 6; ind++)
    {
        QTableWidgetItem* tmp = new QTableWidgetItem(items[ind]);
        tmp->setTextAlignment(Qt::AlignTop | Qt::AlignLeft);
        ui->tableWidget_ACL->setItem(
                    ui->tableWidget_ACL->rowCount() - 1,
                    ind,
                    tmp);
    }
    ui->tableWidget_ACL->resizeColumnsToContents();
    ui->tableWidget_ACL->resizeRowsToContents();
}

void MainWindow::on_pushButton_Save_clicked()
{
    if(saveACE())
    {
        ui->pushButton_New->setEnabled(true);
        ui->widget_Container->setEnabled(false);
        ui->pushButton_Save->setEnabled(false);
        ui->pushButton_Cancel->setEnabled(false);
        ui->tableWidget_ACL->setEnabled(true);

        ui->pushButton_New->setEnabled(true);
        ui->widget_Container->setEnabled(false);
        ui->pushButton_Save->setEnabled(false);
        ui->pushButton_Cancel->setEnabled(false);
        ui->tableWidget_ACL->setEnabled(true);

        revertEditorFormat();

        showACL();
    }
}

void MainWindow::on_tableWidget_ACL_itemDoubleClicked(QTableWidgetItem *item)
{
    ui->pushButton_Delete->setEnabled(false);
    ui->tableWidget_ACL->setEnabled(false);

    if (item->row() != ui->tableWidget_ACL->rowCount() - 1 &&
        ui->tableWidget_ACL->item(ui->tableWidget_ACL->rowCount() - 1, 0)->text() == QString("UNSAVED"))
    {
        return;
    }

    ui->widget_Container->setEnabled(true);
    ui->pushButton_Save->setEnabled(true);
    ui->pushButton_Cancel->setEnabled(true);
    ui->pushButton_New->setEnabled(false);


    ui->checkBox_FILE_LIST_DIRECTORY->   setEnabled(!isFile);
    ui->checkBox_FILE_ADD_FILE->         setEnabled(!isFile);
    ui->checkBox_FILE_ADD_SUBDIRECTORY-> setEnabled(!isFile);
    ui->checkBox_FILE_TRAVERSE->         setEnabled(!isFile);

    ui->checkBox_FILE_READ_DATA->        setEnabled(isFile);
    ui->checkBox_FILE_WRITE_DATA->       setEnabled(isFile);
    ui->checkBox_FILE_APPEND_DATA->      setEnabled(isFile);
    ui->checkBox_FILE_EXECUTE->          setEnabled(isFile);

    if(ui->tableWidget_ACL->item(ui->tableWidget_ACL->rowCount() - 1, 0)->text() == QString("UNSAVED"))
    {
        return;
    }

    int genCntrAll = 0, genCntrR = 0, genCntrW = 0, genCntrE = 0;
    int i = item->row();
    LPTSTR sidStr = NULL;
    PSID pSID = NULL;
    QFont boldFont;
    boldFont.setBold(true);

    revertEditorFormat();

    // Specific
    if ((entryList[i].grfAccessPermissions & 0x01) == 0x01) // FILE_READ_DATA || FILE_LIST_DIRECTORY
    {
        if(isFile)
        {
            genCntrAll++;
            genCntrR++;
            ui->checkBox_FILE_READ_DATA        ->setChecked(true);
        }
        else
        {
            genCntrAll++;
            genCntrR++;
            ui->checkBox_FILE_LIST_DIRECTORY   ->setChecked(true);
        }
    }
    if ((entryList[i].grfAccessPermissions & 0x02) == 0x02) // FILE_WRITE_DATA || FILE_ADD_FILE
    {
        if(isFile)
        {
            genCntrAll++;
            genCntrW++;
            ui->checkBox_FILE_WRITE_DATA       ->setChecked(true);
        }
        else
        {
            genCntrAll++;
            genCntrW++;
            ui->checkBox_FILE_ADD_FILE         ->setChecked(true);
        }
    }
    if ((entryList[i].grfAccessPermissions & 0x04) == 0x04) // FILE_APPEND_DATA || FILE_ADD_SUBDIRECTORY
    {
        if(isFile)
        {
            genCntrAll++;
            genCntrW++;
            ui->checkBox_FILE_APPEND_DATA      ->setChecked(true);
        }
        else
        {
            genCntrAll++;
            genCntrW++;
            ui->checkBox_FILE_ADD_SUBDIRECTORY ->setChecked(true);
        }
    }
    if ((entryList[i].grfAccessPermissions & FILE_READ_EA) == FILE_READ_EA)
    {
        genCntrAll++;
        genCntrR++;
        ui->checkBox_FILE_READ_EA          ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & FILE_WRITE_EA) == FILE_WRITE_EA)
    {
        genCntrAll++;
        genCntrW++;
        ui->checkBox_FILE_WRITE_EA         ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & 0x20) == 0x20) // FILE_EXECUTE || FILE_TRAVERSE
    {
        if(isFile)
        {
            genCntrAll++;
            genCntrE++;
            ui->checkBox_FILE_EXECUTE          ->setChecked(true);
        }
        else
        {
            genCntrAll++;
            genCntrE++;
            ui->checkBox_FILE_TRAVERSE         ->setChecked(true);
        }
    }
    if ((entryList[i].grfAccessPermissions & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
    {
        genCntrAll++;
        ui->checkBox_FILE_DELETE_CHILD     ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
    {
        genCntrAll++;
        genCntrE++;
        genCntrR++;
        ui->checkBox_FILE_READ_ATTRIBUTES  ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
    {
        genCntrAll++;
        genCntrW++;
        ui->checkBox_FILE_WRITE_ATTRIBUTES ->setChecked(true);
    }

    // Standard
    if ((entryList[i].grfAccessPermissions & DELETE) == DELETE)
    {
        genCntrAll++;
        ui->checkBox_DELETE                ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & READ_CONTROL) == READ_CONTROL)
    {
        genCntrAll++;
        genCntrR++;
        genCntrW++;
        genCntrE++;
        ui->checkBox_READ_CONTROL          ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & WRITE_DAC) == WRITE_DAC)
    {
        genCntrAll++;
        ui->checkBox_WRITE_DAC             ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & WRITE_OWNER) == WRITE_OWNER)
    {
        genCntrAll++;
        ui->checkBox_WRITE_OWNER           ->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & SYNCHRONIZE) == SYNCHRONIZE)
    {
        genCntrAll++;
        genCntrR++;
        genCntrW++;
        genCntrE++;
        ui->checkBox_SYNCHRONIZE           ->setChecked(true);
    }

    // Other
    if ((entryList[i].grfAccessPermissions & ACCESS_SYSTEM_SECURITY) == ACCESS_SYSTEM_SECURITY)
    {
        ui->checkBox_ACCESS_SYSTEM_SECURITY->setChecked(true);
    }
    if ((entryList[i].grfAccessPermissions & MAXIMUM_ALLOWED) == MAXIMUM_ALLOWED)
    {
        ui->checkBox_MAXIMUM_ALLOWED       ->setChecked(true);
    }

    // Generic
    if(genCntrAll == 14)
    {
        ui->checkBox_GENERIC_ALL->setChecked(true);

        ui->checkBox_GENERIC_ALL->setFont(boldFont);

        ui->checkBox_FILE_ADD_FILE         ->setFont(boldFont);
        ui->checkBox_FILE_ADD_SUBDIRECTORY ->setFont(boldFont);
        ui->checkBox_FILE_APPEND_DATA      ->setFont(boldFont);
        ui->checkBox_FILE_DELETE_CHILD     ->setFont(boldFont);
        ui->checkBox_FILE_EXECUTE          ->setFont(boldFont);
        ui->checkBox_FILE_LIST_DIRECTORY   ->setFont(boldFont);
        ui->checkBox_FILE_READ_ATTRIBUTES  ->setFont(boldFont);
        ui->checkBox_FILE_READ_DATA        ->setFont(boldFont);
        ui->checkBox_FILE_READ_EA          ->setFont(boldFont);
        ui->checkBox_FILE_TRAVERSE         ->setFont(boldFont);
        ui->checkBox_FILE_WRITE_ATTRIBUTES ->setFont(boldFont);
        ui->checkBox_FILE_WRITE_DATA       ->setFont(boldFont);
        ui->checkBox_FILE_WRITE_EA         ->setFont(boldFont);

        ui->checkBox_DELETE                ->setFont(boldFont);
        ui->checkBox_READ_CONTROL          ->setFont(boldFont);
        ui->checkBox_SYNCHRONIZE           ->setFont(boldFont);
        ui->checkBox_WRITE_DAC             ->setFont(boldFont);
        ui->checkBox_WRITE_OWNER           ->setFont(boldFont);
    }
    else
    {
        if(genCntrR == 5)
        {
            ui->checkBox_GENERIC_READ->setChecked(true);

            ui->checkBox_GENERIC_READ->setFont(boldFont);

            ui->checkBox_FILE_READ_DATA        ->setFont(boldFont);
            ui->checkBox_FILE_LIST_DIRECTORY   ->setFont(boldFont);
            ui->checkBox_FILE_READ_EA          ->setFont(boldFont);
            ui->checkBox_FILE_READ_ATTRIBUTES  ->setFont(boldFont);

            ui->checkBox_READ_CONTROL          ->setFont(boldFont);
            ui->checkBox_SYNCHRONIZE           ->setFont(boldFont);
        }
        else if(genCntrW == 6)
        {
            ui->checkBox_GENERIC_WRITE->setChecked(true);

            ui->checkBox_GENERIC_WRITE->setFont(boldFont);

            ui->checkBox_FILE_WRITE_DATA       ->setFont(boldFont);
            ui->checkBox_FILE_ADD_FILE         ->setFont(boldFont);
            ui->checkBox_FILE_APPEND_DATA      ->setFont(boldFont);
            ui->checkBox_FILE_ADD_SUBDIRECTORY ->setFont(boldFont);
            ui->checkBox_FILE_WRITE_EA         ->setFont(boldFont);
            ui->checkBox_FILE_WRITE_ATTRIBUTES ->setFont(boldFont);

            ui->checkBox_READ_CONTROL          ->setFont(boldFont);
            ui->checkBox_SYNCHRONIZE           ->setFont(boldFont);
        }
        else if(genCntrE == 4)
        {
            ui->checkBox_GENERIC_EXECUTE->setChecked(true);

            ui->checkBox_GENERIC_EXECUTE->setFont(boldFont);

            ui->checkBox_FILE_EXECUTE          ->setFont(boldFont);
            ui->checkBox_FILE_TRAVERSE         ->setFont(boldFont);
            ui->checkBox_FILE_READ_ATTRIBUTES  ->setFont(boldFont);

            ui->checkBox_READ_CONTROL          ->setFont(boldFont);
            ui->checkBox_SYNCHRONIZE           ->setFont(boldFont);
        }
    }


    // AccessMode
    (entryList[i].grfAccessMode == GRANT_ACCESS) ?  ui->comboBox_AccessMode->setCurrentIndex(1) :
    (entryList[i].grfAccessMode == SET_ACCESS) ?    ui->comboBox_AccessMode->setCurrentIndex(2) :
    (entryList[i].grfAccessMode == DENY_ACCESS) ?   ui->comboBox_AccessMode->setCurrentIndex(3) :
    (entryList[i].grfAccessMode == REVOKE_ACCESS) ? ui->comboBox_AccessMode->setCurrentIndex(4) :
                                                    ui->comboBox_AccessMode->setCurrentIndex(0) ;

    // Trustee
    if (entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_SID)
    {
        ui->lineEdit_Username->setText(sidToUsername(entryList[i].Trustee.ptstrName));

        ConvertSidToStringSid(entryList[i].Trustee.ptstrName, &sidStr);
        ui->lineEdit_SID->setText(QString::fromWCharArray(sidStr));
        LocalFree(sidStr);
    }
    else if (entryList[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME)
    {
        ui->lineEdit_Username->setText(QString::fromWCharArray(entryList[i].Trustee.ptstrName));

        pSID = usernameToSid(QString::fromWCharArray(entryList[i].Trustee.ptstrName));
        ConvertSidToStringSid(entryList[i].Trustee.ptstrName, &sidStr);
        ui->lineEdit_SID->setText(QString::fromWCharArray(sidStr));
        LocalFree(sidStr);
        LocalFree(pSID);
    }
    else // TRUSTEE_IS_OBJECTS_AND_NAME || TRUSTEE_IS_OBJECTS_AND_SID
    {
        printf("TODO TRUSTEE_IS_OBJECTS_AND_NAME || TRUSTEE_IS_OBJECTS_AND_SID");
    }
}

void MainWindow::on_pushButton_Cancel_clicked()
{
    ui->pushButton_New->setEnabled(true);
    ui->widget_Container->setEnabled(false);
    ui->pushButton_Save->setEnabled(false);
    ui->pushButton_Cancel->setEnabled(false);
    ui->tableWidget_ACL->setEnabled(true);

    revertEditorFormat();

    if(ui->tableWidget_ACL->item(ui->tableWidget_ACL->rowCount() - 1, 0)->text() == QString("UNSAVED"))
    {
        ui->tableWidget_ACL->removeRow(ui->tableWidget_ACL->rowCount() - 1);
    }
}

void MainWindow::on_pushButton_CheckName_clicked()
{
    PSID pSid = NULL;
    LPTSTR sidStr = NULL;

    pSid = usernameToSid(ui->lineEdit_Username->text());
    ConvertSidToStringSid(pSid, &sidStr);
    ui->lineEdit_SID->setText(QString::fromWCharArray(sidStr));

    LocalFree(sidStr);
    LocalFree(pSid);
}

void MainWindow::on_pushButton_Delete_clicked()
{
    ui->pushButton_Delete->setEnabled(false);

    if(ui->tableWidget_ACL->item(selectedRow, 0)->text() == QString("UNSAVED"))
    {
        ui->pushButton_New->setEnabled(true);
        ui->tableWidget_ACL->removeRow(selectedRow);
        return;
    }

    deleteSelectedAce(selectedRow);
    cleanupGlobals();
    showACL();
}

void MainWindow::on_tableWidget_ACL_itemClicked(QTableWidgetItem *item)
{
    selectedRow = item->row();

    if (ui->tableWidget_ACL->item(ui->tableWidget_ACL->rowCount() - 1, 0)->text() == QString("UNSAVED"))
    {
        if (selectedRow == ui->tableWidget_ACL->rowCount() - 1)
        {
            ui->pushButton_Delete->setEnabled(true);
        }
        else
        {
            ui->pushButton_Delete->setEnabled(false);
        }
    }
    else
    {
        ui->pushButton_Delete->setEnabled(true);
    }
}

void MainWindow::revertEditorFormat()
{
    QFont boldFont;
    boldFont.setBold(false);

    ui->checkBox_GENERIC_ALL->setFont(boldFont);
    ui->checkBox_GENERIC_EXECUTE->setFont(boldFont);
    ui->checkBox_GENERIC_READ->setFont(boldFont);
    ui->checkBox_GENERIC_WRITE->setFont(boldFont);

    ui->checkBox_FILE_ADD_FILE         ->setFont(boldFont);
    ui->checkBox_FILE_ADD_SUBDIRECTORY ->setFont(boldFont);
    ui->checkBox_FILE_APPEND_DATA      ->setFont(boldFont);
    ui->checkBox_FILE_DELETE_CHILD     ->setFont(boldFont);
    ui->checkBox_FILE_EXECUTE          ->setFont(boldFont);
    ui->checkBox_FILE_LIST_DIRECTORY   ->setFont(boldFont);
    ui->checkBox_FILE_READ_ATTRIBUTES  ->setFont(boldFont);
    ui->checkBox_FILE_READ_DATA        ->setFont(boldFont);
    ui->checkBox_FILE_READ_EA          ->setFont(boldFont);
    ui->checkBox_FILE_TRAVERSE         ->setFont(boldFont);
    ui->checkBox_FILE_WRITE_ATTRIBUTES ->setFont(boldFont);
    ui->checkBox_FILE_WRITE_DATA       ->setFont(boldFont);
    ui->checkBox_FILE_WRITE_EA         ->setFont(boldFont);

    ui->checkBox_DELETE                ->setFont(boldFont);
    ui->checkBox_READ_CONTROL          ->setFont(boldFont);
    ui->checkBox_SYNCHRONIZE           ->setFont(boldFont);
    ui->checkBox_WRITE_DAC             ->setFont(boldFont);
    ui->checkBox_WRITE_OWNER           ->setFont(boldFont);

    ui->checkBox_FILE_ADD_FILE         ->setChecked(false);
    ui->checkBox_FILE_ADD_SUBDIRECTORY ->setChecked(false);
    ui->checkBox_FILE_APPEND_DATA      ->setChecked(false);
    ui->checkBox_FILE_DELETE_CHILD     ->setChecked(false);
    ui->checkBox_FILE_EXECUTE          ->setChecked(false);
    ui->checkBox_FILE_LIST_DIRECTORY   ->setChecked(false);
    ui->checkBox_FILE_READ_ATTRIBUTES  ->setChecked(false);
    ui->checkBox_FILE_READ_DATA        ->setChecked(false);
    ui->checkBox_FILE_READ_EA          ->setChecked(false);
    ui->checkBox_FILE_TRAVERSE         ->setChecked(false);
    ui->checkBox_FILE_WRITE_ATTRIBUTES ->setChecked(false);
    ui->checkBox_FILE_WRITE_DATA       ->setChecked(false);
    ui->checkBox_FILE_WRITE_EA         ->setChecked(false);

    ui->checkBox_DELETE                ->setChecked(false);
    ui->checkBox_READ_CONTROL          ->setChecked(false);
    ui->checkBox_SYNCHRONIZE           ->setChecked(false);
    ui->checkBox_WRITE_DAC             ->setChecked(false);
    ui->checkBox_WRITE_OWNER           ->setChecked(false);

    ui->checkBox_ACCESS_SYSTEM_SECURITY->setChecked(false);
    ui->checkBox_MAXIMUM_ALLOWED       ->setChecked(false);

    ui->checkBox_GENERIC_ALL           ->setChecked(false);
    ui->checkBox_GENERIC_EXECUTE       ->setChecked(false);
    ui->checkBox_GENERIC_READ          ->setChecked(false);
    ui->checkBox_GENERIC_WRITE         ->setChecked(false);

    ui->lineEdit_Username->clear();
    ui->lineEdit_SID->clear();

    ui->comboBox_AccessMode->setCurrentIndex(0);
}

