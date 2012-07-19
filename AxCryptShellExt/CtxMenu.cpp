/*
    @(#) $Id$

	Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001 Svante Seleborg/Axon Data, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
	ContextMenu.cpp					IContextMenu implementatino

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
                                    2002-07-26              Ver 1.2

*/

/*
Running the Shell Under a Debugger

To debug your extension, you need to execute the Shell from the debugger. Follow these steps:

Load the extension's project into the debugger, but do not run it.
From the Start menu on the Microsoft Windows taskbar, choose Shut Down.
Press CTRL+ALT+SHIFT, and click No in the Shut Down Windows dialog box. On Windows 2000, click Cancel instead of No.
The Shell is now shut down, but all other applications are still running, including the debugger.
Set the debugger to run the extension DLL with Explorer.exe from the Windows directory.
Run the project from the debugger. The Shell will start up as usual, but the debugger will be attached to the Shell's process.
Running and Testing Shell Extensions on Windows NT
You can run and test your Microsoft Windows NT extensions in a separate Windows Explorer process to avoid stopping and
restarting the desktop and taskbar. Your desktop and taskbar can still be used while you run and test the extensions.

To enable this feature, add the following value to the registry.

HKEY_CURRENT_USER Software Microsoft Windows CurrentVersion Explorer DesktopProcess (REG_DWORD)= 1

For this value to take effect, you must log off and log on again. This setting causes the desktop and taskbar windows to be
created in one Explorer.exe process, and all other Explorer and folder windows to be opened in a different Explorer.exe process.

In addition to making running and testing your extensions more convenient, this setting also makes the desktop more robust as
it relates to Shell extensions. Many such extensions (shortcut menu extensions, for example) will be loaded into the
nondesktop Explorer.exe process. If this process terminates, the desktop and taskbar will be unaffected, and the next Explorer
or folder window will re-create the terminated process.
*/

#include	"StdAfx.h"
#include	"Shellapi.h"
#include	"../AxCryptCommon/CFileName.h"
#include	"process.h"
#include	"AxCryptTexts.h"
#include	"../AxCryptCommon/CVersion.h"
#include	"../AxCryptCommon/Utility.h"
#include	"stdio.h"
#include    "../AxCryptCommon/CRegistry.h"
#include    <memory>
#include     "Shlwapi.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CtxMenu.cpp"
//
#define	VERB_ENCRYPTZ	"encryptz"
#define VERB_ENCRYPTZC  "encryptzc"         ///< Encrypt copy, keep original
#define	VERB_ENCRYPT	"encrypt"
#define VERB_SFXENCDEF  "sfxencdef"         ///< SFX to new default name, one by one
#define VERB_SFXENCNAME "sfxencname"        ///< SFX to new given name, all in one
#define	VERB_DECRYPT	"decrypt"
#define	VERB_OPEN		"openaxx"
#define	VERB_WIPE		"wipe"
#define VERB_DEBUG      "debug"
#define VERB_CLEARKEYS  "clearkeys"
#define VERB_RENAME     "renameanon"
#define VERB_BRUTEFORCE "bruteforce"
#define VERB_HEXCOPY    "hexcopy"
#define VERB_KEYFILE    "keyfile"
#define VERB_NOTIFYME   "notifyme"
#define VERB_DOCS       "docs"
#define VERB_ABOUT      "about"
#define VERB_BUGREPORT  "bugreport"         ///< Launch a bug-report info/web if one is given
#define VERB_LICENSEMGR "licensemgr"
#define VERB_ENGLISH    "english"           ///< Select user interface language to english
#define VERB_DANISH     "danish"            ///< Select user interface language to danish
#define VERB_GERMAN     "german"            ///< Select user interface language to german
#define VERB_DUTCH      "dutch"             ///< Select user interface language to dutch
#define VERB_HUNGARIAN  "hungarian"         ///< Select user interface language to hungarian
#define VERB_SPANISH    "spanish"           ///< Select user interface language to spanish
#define VERB_FRENCH     "french"            ///< Select user interface language to french
#define VERB_ITALIAN    "italian"           ///< Select user interface language to italian
#define VERB_NORWEGIAN  "norwegian"         ///< Select user interface language to norwegian
#define VERB_SWEDISH    "swedish"           ///< Select user interface language to swedish
#define VERB_BRAZILPORTUGUESE "brazilportuguese"    ///< Select user interface language to brazilian portuguese
#define VERB_POLISH     "polish"            ///< Select user interface language to polish
#define VERB_RUSSIAN    "russian"            ///< Select user interface language to russian

//
struct CShellExt::SVerbs CShellExt::m_Verbs[] = {
	{VERB_OPEN, INF_MENU_OPEN, HLP_MENU_OPEN, 0, &DoOpen},
	{VERB_ENCRYPTZ, INF_MENU_WRAPZ, HLP_MENU_WRAPZ, 0, &DoEncryptCompress},
    {VERB_ENCRYPTZC, INF_MENU_WRAPZC, HLP_MENU_WRAPZC, 0, &DoEncryptCompressCopy},
    {VERB_SFXENCDEF, INF_MENU_SFXENCDEF, HLP_MENU_SFXENCDEF, 0, &DoSfxEncDef},
    {VERB_SFXENCNAME, INF_MENU_SFXENCNAME, HLP_MENU_SFXENCNAME, 0, &DoSfxEncName},
    {VERB_ENCRYPT, INF_MENU_WRAP, HLP_MENU_WRAP, 0, &CShellExt::DoEncryptOnly},
	{VERB_DECRYPT, INF_MENU_UNWRAP, HLP_MENU_UNWRAP, 0, &CShellExt::DoDecrypt},
	{VERB_WIPE, INF_MENU_WIPE, HLP_MENU_WIPE, 0, &CShellExt::DoWipe},
	{VERB_DEBUG, INF_MENU_DEBUG, HLP_MENU_DEBUG, 0, &CShellExt::DoDebug},
    {VERB_CLEARKEYS, INF_MENU_CLEARKEYS, HLP_MENU_CLEARKEYS, 0, &CShellExt::DoClearKeys},
    {VERB_RENAME, INF_MENU_RENAME, HLP_MENU_RENAME, 0, &CShellExt::DoRename},
    {VERB_BRUTEFORCE, INF_MENU_BRUTEFORCE, HLP_MENU_BRUTEFORCE, 0, &CShellExt::DoBruteForce},
    {VERB_HEXCOPY, INF_MENU_HEXCOPY, HLP_MENU_HEXCOPY, 0, &CShellExt::DoHexCopy},
    {VERB_KEYFILE, INF_MENU_KEYFILE, HLP_MENU_KEYFILE, 0, &CShellExt::DoKeyFile},
    {VERB_NOTIFYME, INF_MENU_NOTIFYME, HLP_MENU_NOTIFYME, 0, &CShellExt::DoNotifyMe},
    {VERB_DOCS, INF_MENU_DOCS, HLP_MENU_DOCS, 0, &CShellExt::DoDocs},
    {VERB_ABOUT, INF_MENU_ABOUT, HLP_MENU_ABOUT, 0, &CShellExt::DoAbout},
    {VERB_BUGREPORT, INF_MENU_BUGREPORT, HLP_MENU_BUGREPORT, 0, &CShellExt::DoBugReport},
    {VERB_LICENSEMGR, INF_MENU_LICENSEMGR, HLP_MENU_LICENSEMGR, 0, &CShellExt::DoLicenseMgr},
    {VERB_ENGLISH, INF_MENU_ENGLISH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoEnglish},
    {VERB_DANISH, INF_MENU_DANISH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoDanish},
    {VERB_GERMAN, INF_MENU_GERMAN, HLP_MENU_LANGUAGE, 0, &CShellExt::DoGerman},
    {VERB_DUTCH, INF_MENU_DUTCH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoDutch},
    {VERB_HUNGARIAN, INF_MENU_HUNGARIAN, HLP_MENU_LANGUAGE, 0, &CShellExt::DoHungarian},
    {VERB_SPANISH, INF_MENU_SPANISH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoSpanish},
    {VERB_FRENCH, INF_MENU_FRENCH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoFrench},
    {VERB_ITALIAN, INF_MENU_ITALIAN, HLP_MENU_LANGUAGE, 0, &CShellExt::DoItalian},
    {VERB_NORWEGIAN, INF_MENU_NORWEGIAN, HLP_MENU_LANGUAGE, 0, &CShellExt::DoNorwegian},
    {VERB_SWEDISH, INF_MENU_SWEDISH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoSwedish},
    {VERB_BRAZILPORTUGUESE, INF_MENU_BRAZILPORTUGUESE, HLP_MENU_LANGUAGE, 0, &CShellExt::DoBrazilPortuguese},
    {VERB_POLISH, INF_MENU_POLISH, HLP_MENU_LANGUAGE, 0, &CShellExt::DoPolish},
    {VERB_RUSSIAN, INF_MENU_RUSSIAN, HLP_MENU_LANGUAGE, 0, &CShellExt::DoRussian},
    {"", 0, 0, -1, &CShellExt::DoNothing}
};

/// \brief Get the path based on the pidl
/// \return The path, or empty
static axpl::ttstring
GetPath(IShellFolder *pShellFolder, LPCITEMIDLIST pidl) {
    STRRET strret;
    HRESULT hRes;

    //
    // Getting the display name of certain objects is not supported on Win98, and probably
    // WinNT, notably this occurs when right-clicking a computer in the network neighborhood.
    // Thus we try to be tolerant, but do log the event if it happens.
    //
    hRes = pShellFolder->GetDisplayNameOf(pidl, SHGDN_NORMAL | SHGDN_FORPARSING, &strret);
    if (FAILED(hRes)) {
        CMessage().Wrap(0).AppMsg(MSG_SYSTEM_CALL, CMessage().SysMsg(hRes).GetMsg(), _T("CFileObjectList::GetPath [GetDisplayNameOf]")).LogEvent(1);
        return axpl::ttstring();
    }

    // Here we do not really know what the format returned will be...
    switch (strret.uType) {
    case STRRET_CSTR:
        return axpl::s2t(strret.cStr);
        break;
    case STRRET_OFFSET:
        CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CFileObjectList::GetPath [STRRET_OFFSET]")).Throw();
        break;
    case STRRET_WSTR:
        {
            axpl::ttstring s = axpl::w2t(strret.pOleStr);
            gpMalloc->Free(strret.pOleStr);
            return s;
        }
        break;
    default:
        CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CFileObjectList::GetPath [Unknown]")).Throw();
        break;
    }
    return axpl::ttstring();
}
//
//  Simple helper to test if a file is possible to open for write,
//  this is to make sure we only refresh the Windows Explorer
//  if necessary.
//
static BOOL
IsReadOnly(LPCTSTR szFileName) {
    DWORD dwAttrib = GetFileAttributes(szFileName);
    CAssert(dwAttrib != INVALID_FILE_ATTRIBUTES).Sys(MSG_SYSTEM_CALL, _T("IsReadOnly [GetFileAttributes]")).Throw();
    return (dwAttrib & FILE_ATTRIBUTE_READONLY) != 0;
}

static BOOL
CanOpenForWrite(LPCTSTR szFileName) {
    HANDLE hFile = CreateFile(
        szFileName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return hFile != INVALID_HANDLE_VALUE;
}
//
//  Return true if it is a regular encrypteable/decryptable file
//
static BOOL
IsFile(IShellFolder *pShellFolder, LPCITEMIDLIST pidl) {
    axpl::ttstring sPath = GetPath(pShellFolder, pidl);
    if (sPath.empty()) {
        return false;
    }

    HRESULT hRes;
    ULONG rgf = SFGAO_FOLDER|SFGAO_FILESYSTEM ;
    hRes = pShellFolder->GetAttributesOf(1, &pidl, &rgf);
    if (!SUCCEEDED(hRes)) {
        CAssert(FALSE, hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IsFile [GetAttributesOf]")).Throw();
    }

    // Some tricks are necessary to handle .zip files and other such-like extensions in XP. They are viewed
    // as folders by the shell, but not by the file system. In XP, they do not have the SFGAO_FILESYSANCESTOR
    // set, but then neither does regular folders in Win9x, so we can't use that. Instead we check the
    // actual file attributes too, as we can't be sure just
    DWORD dwAttrib = GetFileAttributes(sPath.c_str());
    if (dwAttrib != 0xFFFFFFFF) {
        // The net effect here is to disregard the shells opinion, if the file system insists that the
        // object is a file. We could probably skip asking the shell completely, but it feels good having
        // this here for the future when this mess maybe gets cleared up and we don't have to support Win9x
        // anymore.
        if ((rgf & SFGAO_FOLDER) == 0 || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            if ((dwAttrib & (FILE_ATTRIBUTE_DIRECTORY |
                             FILE_ATTRIBUTE_OFFLINE |
                             FILE_ATTRIBUTE_SYSTEM)) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}
//
//  Determine if a file is an ax crypt encrypted file.
//
//  This is done by ensuring that it's not a folder, and that the
//  name ends with .xxx. In the future, one might go further and actually
//  examine the file itself.
//
static BOOL
IsEncrypted(IShellFolder *pShellFolder, LPCITEMIDLIST pidl) {
    if (IsFile(pShellFolder, pidl)) {
        CFileName fn(GetPath(pShellFolder, pidl).c_str());
        return _wcsicmp(fn.GetExt(), gszAxCryptFileExt) == 0;
    }
    return FALSE;
}

static BOOL
IsFolder(IShellFolder *pShellFolder, LPCITEMIDLIST pidl) {
    HRESULT hRes;
    ULONG rgf = SFGAO_FOLDER|SFGAO_FILESYSTEM;
    hRes = pShellFolder->GetAttributesOf(1, &pidl, &rgf);
    CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IsFolder [GetAttributesOf]")).Throw();
    // Some tricks are necessary to handle .zip files and other such-like extensions in XP. They are viewed
    // as folders by the shell, but not by the file system. In XP, they do not have the SFGAO_FILESYSANCESTOR
    // set, but then neither does regular folders in Win9x, so we can't use that. Instead we do a double
    // test, and also check the actual file attributes.
    if ((rgf & SFGAO_FOLDER) != 0 && (rgf & SFGAO_FILESYSTEM) != 0) {
        DWORD dwAttrib = GetFileAttributes(GetPath(pShellFolder, pidl).c_str());
        if (dwAttrib != 0xFFFFFFFF) {
            if ((dwAttrib & FILE_ATTRIBUTE_DIRECTORY) &&
                (dwAttrib & (FILE_ATTRIBUTE_OFFLINE |
                             FILE_ATTRIBUTE_SYSTEM)) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

CFileObjectList::CFileObjectList() {
    try {
        m_pDataObj = NULL;
        m_pidlShellFolder = NULL;
        m_pShellFolder = NULL;
        //m_pShellView = NULL; // No use any more - explorer gets confused when
        // trying to do refresh from the worker thread, presumably the actual view
        // has changed into a new one (which was the whole point of the worker thread...)
        //m_pShellBrowser = NULL;
        m_pDesktopFolder = NULL;

        m_hShellFolderWnd = NULL;
        m_hProgressWnd = NULL;
        m_pCIDA = NULL;
        m_fShellViewHasBeenReset = FALSE;

        HRESULT hRes = SHGetDesktopFolder(&m_pDesktopFolder);
        CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::CFileObjectList [SHGetDesktopFolder]")).Throw();

        //InitIteration();
    } catch (TAssert utErr) {
        utErr.Show();
    }
}

CFileObjectList::~CFileObjectList() {
    try {
        EndIteration();
        if (m_pDataObj) m_pDataObj->Release();
        if (m_pShellFolder) m_pShellFolder->Release();
        if (m_pidlShellFolder) gpMalloc->Free(m_pidlShellFolder);
        //if (m_pShellView) m_pShellView->Release();
        //if (m_pShellBrowser) m_pShellBrowser->Release();
        if (m_pDesktopFolder) m_pDesktopFolder->Release();
    } catch (TAssert utErr) {
        utErr.Show();
    }
}
//
//  Save a refeference pointer to the selection object, and
//  initialize the iteration.
//
void
CFileObjectList::SetObject(IDataObject *pdObj) {
	// We may be called more than once
	if (m_pDataObj) m_pDataObj->Release();

    // Save the object
	if (pdObj) {
		m_pDataObj = pdObj;
		pdObj->AddRef();
        InitIteration();
    } else {
        m_pDataObj = NULL;
    }
}

// This is removed, since among other things, the IShellBrowser interface, and thus
// the GETISHELLBROWSER windows message is not supported by various Windows Explorer
// replacements. Also, the GETISHELLBROWSER message is still not really documented.
// 2005-03-04 /SS
#ifdef DEADCODE
void
CFileObjectList::SetActiveShellView(HWND hWnd) {
    HRESULT hRes;
    if (hWnd && m_hShellFolderWnd == NULL) {
        m_hShellFolderWnd = hWnd;
	    m_pShellBrowser = (IShellBrowser *)SendMessage(hWnd, WM_USER + 7, 0, 0L);
        if (m_pShellBrowser != NULL) {
            m_pShellBrowser->AddRef();
	        if (FAILED(hRes = m_pShellBrowser->QueryActiveShellView(&m_pShellView))) {
                m_pShellView = NULL;
            }
        }
    }
}
#endif
//
//  Return number of items selected
//
int
CFileObjectList::ItemsSelected() {
    return m_pCIDA != NULL ? m_pCIDA->cidl : 0;
}
//
//  TRUE if exactly one _file_ is selected
//
BOOL
CFileObjectList::SelectionIsOneFile() {
    return (ItemsSelected() == 1 &&
            IsFile(m_pShellFolder, (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]]));
}
/// Check if the selection is exactly one folder
/// \return TRUE if the selection represents exactly one folder
BOOL
CFileObjectList::SelectionIsOneFolder() {
    return (ItemsSelected() == 1 &&
            IsFolder(m_pShellFolder, (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]]));
}
//
//  TRUE if it is our opinion that the property sheet is appropriate for
//  the selection.
//
BOOL
CFileObjectList::ShowPropertySheet() {
    if (ItemsSelected() == 1) {
        LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
        return IsEncrypted(m_pShellFolder, pidl);
    } else {
        return FALSE;
    }
}
//
//  TRUE if it is our opinion that the 'open' menu is appropriate for
//  the selection.
//
BOOL
CFileObjectList::ShowOpenMenu() {
    // If we have a selection and if only one file is selected.
    if (ItemsSelected() == 1) {
        return IsEncrypted(m_pShellFolder, (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]]);
    } else {
        return FALSE;
    }
}
//
//  TRUE if it is our opinion that the 'encrypt' menu is appropriate for
//  the selection.
//
BOOL
CFileObjectList::ShowEncryptMenu() {
    if (ItemsSelected() == 1) {
        LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
        if (SelectionIsOneFile()) {
            return !IsEncrypted(m_pShellFolder, pidl);
        } else {
            return IsFolder(m_pShellFolder, pidl);
        }
    } else {
        return ItemsSelected() > 0;
    }
}
//
//  TRUE if it is our opinion that the 'decrypt' menu is appropriate for
//  the selection.
//
BOOL
CFileObjectList::ShowDecryptMenu() {
	if (gfNoDecryptMode) {
		return FALSE;
	}
    if (ItemsSelected() == 1) {
        LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
        return IsFolder(m_pShellFolder, pidl) || IsEncrypted(m_pShellFolder, pidl);
    } else {
        return ItemsSelected() > 0;
    }
}
/// \brief Test for conditions to show Make Keyfile menu
/// We always show the Make Keyfile menu.
/// \return TRUE if we are to show Make Keyfile
BOOL
CFileObjectList::ShowMakeKeyFileMenu() {
    return TRUE;
}
//
//  TRUE if it is our opinion that the 'wipe' menu is appropriate for
//  the selection.
//
BOOL
CFileObjectList::ShowWipeMenu() {
    if (ItemsSelected() == 1) {
        LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];

#ifdef _DEBUG
        // We're investigating handling wiping of the recycler, but it's not done at this point.
        // Check if the pidl represents the recycler
        ITEMIDLIST *pidlRecycleBin;
        HRESULT hRes = SHGetSpecialFolderLocation(NULL, CSIDL_BITBUCKET, &pidlRecycleBin);
        CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::ShowWipeMenu [SHGetSpecialFolderLocation]")).Throw();

        // now we can compare the PIDLs
		hRes = m_pShellFolder->CompareIDs(0, pidl, pidlRecycleBin);
        // If they are the same, return true
        if (HRESULT_CODE(hRes) == 0) {
            return true;
        }
#endif
        return IsFolder(m_pShellFolder, pidl) || IsFile(m_pShellFolder, pidl);
    } else {
        return ItemsSelected() > 0;
    }
}
//
// TRUE if it is our opinion that the 'rename' menu is appropriate.
//
BOOL
CFileObjectList::ShowRenameMenu() {
	CRegistry utRegKey(HKEY_CURRENT_USER, gszAxCryptRegKey);
    if (utRegKey.Value(szRegValNoRenameMenu).GetDword(FALSE)) {
        return FALSE;
    }

    if (ItemsSelected() == 1) {
        LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
        return IsFolder(m_pShellFolder, pidl) || IsEncrypted(m_pShellFolder, pidl);
    } else {
        return ItemsSelected() > 0;
    }
}
//
//  TRUE if we should show the brute force menu option.
//
BOOL
CFileObjectList::ShowBruteForceMenu() {
    HMODULE hAxBruteDll = LoadLibrary(CFileName().SetPath2ExeName(ghInstance).SetTitle((LPTSTR)szAxBruteDLL).Get());
    bool fHaveDll = hAxBruteDll != NULL;
    if (fHaveDll) {
        FreeLibrary(hAxBruteDll);
        if (ItemsSelected() == 1) {
            LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
            return IsEncrypted(m_pShellFolder, pidl);
        }
    }
    return FALSE;
}
//
//  TRUE if we should show the Hex Copy menu option.
//
BOOL
CFileObjectList::ShowHexCopyMenu() {
    if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValTryBrokenFile).GetDword(FALSE)) {
        if (ItemsSelected() == 1) {
            LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
            return IsEncrypted(m_pShellFolder, pidl);
        }
    }
    return FALSE;
}
//
//  TRUE if we should show the notify me menu option
//
BOOL
CFileObjectList::ShowNotifyMeMenu() {
    return FALSE;                           // Disabled in the context menu, accessible via 'about'
    std::auto_ptr<TCHAR> szNotifyName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValAfterNotifyName).GetSz(_T("")));
    if (szNotifyName.get() && szNotifyName.get()[0]) {
        if (GetFileAttributes(CFileName().SetPath2ExeName(ghInstance).SetTitle(szNotifyName.get()).Get()) != INVALID_FILE_ATTRIBUTES) {
            return TRUE;
        }
    }
    return FALSE;
}
//
//  TRUE if we should show the documentation menu option
//
BOOL
CFileObjectList::ShowDocsMenu() {
    return FALSE;                           // Disabled in the context menu, accessible via 'about'

    std::auto_ptr<TCHAR> szDocumentationName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDocumentationName).GetSz(_T("")));
    if (szDocumentationName.get()[0]) {
        return TRUE;
    }
    return FALSE;
}
/// \brief Test for conditions to show Bug Report menu
/// We always show the Bug Report menu, but only if we have a path/URL or something
/// \return TRUE if we are to show Bug Report
BOOL
CFileObjectList::ShowBugReportMenu() {
    std::auto_ptr<TCHAR> szBugReport(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValBugReport).GetSz(_T("")));
    if (szBugReport.get()[0]) {
        return TRUE;
    }
    return FALSE;
}

BOOL
CFileObjectList::ShowActivationMenu() {
    BOOL fShow = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValShowActivationMenu).GetDword(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValShowActivationMenu).GetDword(FALSE));
    if (!!fShow) {
        return TRUE;
    }
    return FALSE;
}

/// Check if exactly one item is selected, and then get the base title, or
/// or directory name without the path. If more than one item is selected
/// or for other reasons, NULL is returned.
/// \return Pointer to allocated buffer with name or ""
LPTSTR
CFileObjectList::GetTitle() {
    if (ItemsSelected() != 1) {
        return _tcsdup(_T(""));
    }
    LPCITEMIDLIST pidl = (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[1]];
    return _tcsdup(CFileName(GetPath(m_pShellFolder, pidl).c_str()).GetTitle());
}

//
//  Iterate over the selection, calling the call back command handler, first
//  once to do possible one-time things, and then for each item in the selection,
//  expanding folders into files as appropriate.
//
void
CFileObjectList::IterateAll(CShellExt *pShellExt, pfCmdHandlerT pfCmdHandler) {
    // First let the command handler init or perform once-only operations. We will
    // only continue and iterate if the return value is zero.
    CParam *pNewParam = NULL;
    DWORD dwRet = (pShellExt->*pfCmdHandler)(IT_INIT, NULL, m_pDesktopFolder, m_pidlShellFolder, &pNewParam);
    std::auto_ptr<CParam> pParam(pNewParam); // Ensure proper deletion
    if (dwRet == 0) {
        CProgressDialog dlgProgress;
		if (!IsWindow(m_hShellFolderWnd)) {
			m_hShellFolderWnd = NULL;
		}
        m_hProgressWnd = dlgProgress.Create(ghInstance, IDD_PROGRESS, m_hShellFolderWnd, CVersion(ghInstance).String(gfAxCryptShowNoVersion));

        LPCITEMIDLIST pidl;
        BOOL fFileSeen = FALSE;
        while (GetWindowLongPtr(GetParent(m_hProgressWnd), GWLP_USERDATA) && dwRet == 0 && (pidl = Iterate()) != NULL) {
            fFileSeen = fFileSeen || IsFile(m_pShellFolder, pidl);
            dwRet = IteratePidl(m_pShellFolder, pidl, pShellExt, pfCmdHandler, &pNewParam);
        }
        if (dwRet == 0) {
            dwRet = (pShellExt->*pfCmdHandler)(IT_END, NULL, m_pDesktopFolder, m_pidlShellFolder, &pNewParam);
        }
        if (fFileSeen) {
            ShellNotify(m_pDesktopFolder, m_pidlShellFolder, SHCNE_UPDATEDIR);
        }
    }
}
//
//  Setup the memory objects for the iteration over the selection. Use the given
//  data object, and get it in the format of a SHELLIDLIST, i.e. an array of
//  pidls.
//
void
CFileObjectList::InitIteration() {
    HRESULT hRes;
    EndIteration();

    FORMATETC fmtetc = {0, (DVTARGETDEVICE FAR *)NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
	fmtetc.cfFormat = RegisterClipboardFormat(CFSTR_SHELLIDLIST);

    hRes = m_pDataObj->GetData(&fmtetc, &m_StgMedium);
    // See [ 1892655 ] CFileObjectList::InitIteration Invalid FORMATETC structure
    // This should really be fixed by accepting CF_HDROP as well, but right now we attempt to fail silently.
    //CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::InitIteration [GetData]")).Throw();
    if (!SUCCEEDED(hRes)) {
        m_pCIDA = NULL;
        return;
    }

    CAssert((m_pCIDA = (CIDA *)GlobalLock(m_StgMedium.hGlobal)) != NULL).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList.:InitIteration [GlobalLock]")).Throw();
    // if there is any selection...
	if (m_pCIDA->cidl > 0) {
	    ITEMIDLIST *pidlFolder = (ITEMIDLIST *)&((char *)m_pCIDA)[m_pCIDA->aoffset[0]];
        // If a folder is given...
        if (pidlFolder->mkid.cb) {
            // ... we get a new ShellFolder object for this one.
            IShellFolder *psf;
            hRes = m_pDesktopFolder->BindToObject(pidlFolder, NULL, IID_IShellFolder, (LPVOID *)&psf);
            CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList.:InitIteration [BindToObject]")).Throw();
            m_pShellFolder = psf;
            m_pidlShellFolder = CopyPidl(gpMalloc, pidlFolder);
        }
        m_iItemIndex = 1;
        m_fShellViewHasBeenReset = FALSE;
    }
    if (m_pShellFolder == NULL) {
        m_pShellFolder = m_pDesktopFolder;
        m_pShellFolder->AddRef();
        hRes = SHGetSpecialFolderLocation(m_hShellFolderWnd, CSIDL_DESKTOP, &m_pidlShellFolder);
        CAssert(hRes == NOERROR, hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::InitIteration [SHGetSpecialFolderLocation]")).Throw();
    }
}
//
//  Get next item from the selection
//
LPCITEMIDLIST
CFileObjectList::Iterate() {
    if (m_pCIDA && m_iItemIndex <= m_pCIDA->cidl) {
		return (LPCITEMIDLIST)&((char *)m_pCIDA)[m_pCIDA->aoffset[m_iItemIndex++]];
    } else {
        return NULL;
    }
}
//
//  Call the call back for an item, expanding recursively into folders as appropriate.
//
DWORD
CFileObjectList::IteratePidl(IShellFolder *pShellFolder, LPCITEMIDLIST pidl, CShellExt *pShellExt, pfCmdHandlerT pfCmdHandler, CParam **ppParam) {
    // If it's a folder, we recurse.
    DWORD dwRet = 0;
    IShellFolder *pShellSubFolder = NULL;
    IEnumIDList *pEnumIDList = NULL;
    try {
        if (IsFolder(pShellFolder, pidl)) {
            // Set the progress window file name properly
            SetDlgItemText(GetParent(m_hProgressWnd), IDS_FILE, GetPath(pShellFolder, pidl).c_str());
            // Let the do-code have a go at the folder too. (Note for the future - we could
            // push the Param struct here, as we're recursing which for the wipe code at least
            // will let it return to it's previous state after descending into a directory. This
            // could happen in a multi-selection, where for some reason some files are first
            // handled, then a directory appears, then more files. It might be a bit confusing.
            dwRet = (pShellExt->*pfCmdHandler)(IT_FOLDER, m_hProgressWnd, pShellFolder, pidl, ppParam);

            HRESULT hRes;

            // Check if the pidl represents the desktop already, we can't bind to it then the same way
            ITEMIDLIST *pidlDesktop;
            hRes = SHGetSpecialFolderLocation(m_hShellFolderWnd, CSIDL_DESKTOP, &pidlDesktop);
            CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IteratePidl [SHGetSpecialFolderLocation]")).Throw();

            // now we can compare the PIDLs
			hRes = pShellFolder->CompareIDs(0, pidl, pidlDesktop);

            // If they are the same, just clone the desktop IShellFolder *
            if (HRESULT_CODE(hRes) == 0) {
                m_pDesktopFolder->AddRef();
                pShellSubFolder = m_pDesktopFolder;
            } else {
                hRes = pShellFolder->BindToObject(pidl, NULL, IID_IShellFolder, (LPVOID *)&pShellSubFolder);
                CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IteratePidl [BindToObject]")).Throw();
            }

			// Determine if we should 'see' hidden files as well. This may not be implemented on Win95/2k all versions,
			// it may depend on the version of IE installed (version 4), so we load the address dynamically and if we
			// can't find it we do the 'safe' thing and let the shell decide without our interference. Otherwise the idea
			// is that if the user sees the hidden files - so do we. If the hidden files really are hidden, we don't
			// see them. [BUG 1005395]
			HMODULE hShell32 = LoadLibrary(_T("shell32.dll"));
			bool fSeeHiddenFiles = false;
			if (hShell32) {
				typedef void (STDAPICALLTYPE *pfSHGetSettingsT)(LPSHELLFLAGSTATE lpsfs, DWORD dwMask);
				pfSHGetSettingsT pfSHGetSettings = (pfSHGetSettingsT)GetProcAddress(hShell32, "SHGetSettings");
				if (pfSHGetSettings) {
					SHELLFLAGSTATE sfs;
					ZeroMemory(&sfs, sizeof sfs);
					(*pfSHGetSettings)(&sfs, SSF_SHOWALLOBJECTS );
					fSeeHiddenFiles = sfs.fShowAllObjects != FALSE;
				}
				CAssert(FreeLibrary(hShell32)).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IteratePidl [FreeLibrary]")).Throw();
				hShell32 = NULL;
			}

			hRes = pShellSubFolder->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS | (fSeeHiddenFiles ? SHCONTF_INCLUDEHIDDEN : 0), &pEnumIDList);
            CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IteratePidl [EnumbObjects]")).Throw();

            ITEMIDLIST *pidlEnum;
            while (dwRet == 0 && (hRes = pEnumIDList->Next(1, &pidlEnum, NULL)) == S_OK) {
                dwRet = IteratePidl(pShellSubFolder, pidlEnum, pShellExt, pfCmdHandler, ppParam);
                gpMalloc->Free(pidlEnum);
            }
            pEnumIDList->Release(); pEnumIDList = NULL;
            pShellSubFolder->Release(); pShellSubFolder = NULL;
            if (dwRet == 0) {
                dwRet = (pShellExt->*pfCmdHandler)(IT_END_FOLDER, m_hProgressWnd, pShellFolder, pidl, ppParam);
                CAssert(hRes == S_FALSE, hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::IteratePidl [Next]")).Throw();
                if (dwRet == INF_IT_FOLDER_DEL) {
                    ShellNotify(pShellFolder, pidl, SHCNE_RMDIR);
                    dwRet = 0;
                } else {
                    ShellNotify(pShellFolder, pidl, SHCNE_UPDATEDIR);
                }
            }
            // If not abort due to server error, check that the enumeration ended properly.
        } else if (IsFile(pShellFolder, pidl)) {
            axpl::ttstring sFile = GetPath(pShellFolder, pidl);
            // Try to ensure source writeability by forcing a refresh of the view
            // if there is a problem opening the file for writing.
            if (!m_fShellViewHasBeenReset) {
                if (!IsReadOnly(sFile.c_str()) && !CanOpenForWrite(sFile.c_str())) {
                    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSH, NULL, NULL);
                    m_fShellViewHasBeenReset = TRUE;
                }
            }
            // Set the progress window file name properly
            SetDlgItemText(GetParent(m_hProgressWnd), IDS_FILE, sFile.c_str());
            dwRet = (pShellExt->*pfCmdHandler)(IT_FILE, m_hProgressWnd, pShellFolder, pidl, ppParam);
        }
    } catch (TAssert utErr) {
        if (pEnumIDList != NULL) pEnumIDList->Release();
        if (pShellSubFolder != NULL) pShellSubFolder->Release();
        utErr.Throw();
    }
    return dwRet;
}
//
//  Release the memory objects used to iterate over the selection.
//
void
CFileObjectList::EndIteration() {
    if (m_pCIDA) {
        GlobalUnlock(m_pCIDA);
        m_pCIDA = NULL;
        ReleaseStgMedium(&m_StgMedium);
        ZeroMemory(&m_StgMedium, sizeof m_StgMedium);
    }
}
//
//  Notify the shell of a change. Take the pidl, re-interpret it relative to the
//  desktop, and notify.
//
void
CFileObjectList::ShellNotify(IShellFolder *pShellFolder, LPCITEMIDLIST pidl, LONG lEvent) {
    //
    // Due to differences in OS's, we can't reinterpret a pidl that's already desktop relative,
    // as GetDisplayNameOf() will then return 'Desktop' on Win 9x - which is not parseable by ParseDisplayName().
    // It's anyway silly to re-interpret something that's ok to start with...
    //
    if (pShellFolder != m_pDesktopFolder) {
        STRRET strret;
        HRESULT hRes;
        ITEMIDLIST *pidlDesktopRelative = NULL;

        hRes = pShellFolder->GetDisplayNameOf(pidl, SHGDN_NORMAL | SHGDN_FORPARSING, &strret);
        CAssert(SUCCEEDED(hRes), hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::ShellNotify [GetDisplayNameOf]")).Throw();

        // SHGDN_FORPARSING is a lie! It does not necessarily return a useful string, it's just a hint
        // according to updated information, so we need to be tolerant to this.
        ULONG lEaten;
        switch (strret.uType) {
        case STRRET_WSTR:
            hRes = m_pDesktopFolder->ParseDisplayName(m_hShellFolderWnd, NULL, strret.pOleStr, &lEaten, &pidlDesktopRelative, NULL);
            gpMalloc->Free(strret.pOleStr);
            break;
        case STRRET_CSTR: {
            WCHAR *wzName = CopySzWz(strret.cStr);
            hRes = m_pDesktopFolder->ParseDisplayName(m_hShellFolderWnd, NULL, wzName, &lEaten, &pidlDesktopRelative, NULL);
            delete wzName;
            break;
        }
        default:
            CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CFileObjectList::ShellNotify [GetDisplayNameOf]")).Throw();
        }
        // This is not a good situation, but we just log the problem at verbosity level 1, and silently
        // continue.
        if (FAILED(hRes)) {
            CMessage().Wrap(0).AppMsg(MSG_SYSTEM_CALL, CMessage().SysMsg(hRes).GetMsg(), _T("CFileObjectList::ShellNotify [ParseDisplayName]")).LogEvent(1);
            // CAssert(hRes == NOERROR, hRes).Sys(MSG_SYSTEM_CALL, _T("CFileObjectList::ShellNotify [ParseDisplayName]")).Throw();
        } else {
            SHChangeNotify(lEvent, SHCNF_IDLIST | SHCNF_FLUSH, pidlDesktopRelative, NULL);
            gpMalloc->Free(pidlDesktopRelative);
        }
    } else {
        SHChangeNotify(lEvent, SHCNF_IDLIST | SHCNF_FLUSH, pidl, NULL);
    }
    return;
}
//
//	Adds menu items to the specified menu. The menu items should be inserted
//	in the menu at the position specified by indexMenu, and their menu item
//	identifiers must be between the idCmdFirst and idCmdLast parameter values.
//
//	Returns anHRESULT structure in which, if the method is successful,
//	the code member contains the menu identifier of the last menu item added plus one.
//	hMenu
//		Handle to the menu. The handler should specify this handle when
//		adding menu items.
//	indexMenu
//		Zero-based position at which to insert the first menu item.
//	idCmdFirst
//		Minimum value that the handler can specify for a menu item identifier.
//	idCmdLast
//		Maximum value that the handler can specify for a menu item identifier.
//	uFlags
//		Optional flags specifying how the context menu can be changed.
//		The remaining bits of the low-order word are reserved by the system.
//		The high-order word may be used for context-specific communications.
//
//	The actual identifier of each menu item should be idCmdFirst plus a menu identifier
//	offset in the range zero through (idCmdLast - idCmdFirst).
//
STDMETHODIMP
CShellExt::QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags) {
    UINT idCmd = idCmdFirst;
    try {
        // If via explorer, or on the desktop but not a double-click...[BUG 1031514]
	    if (((uFlags & CMF_EXPLORE) || ((uFlags & 0xf) == CMF_NORMAL)) && !(uFlags & CMF_DEFAULTONLY)) {
            try {
                BOOL fDefaultSet = FALSE, fAnyFileOp = FALSE;
	            m_hMenu = CreatePopupMenu();
	            InitVerbs(m_Verbs);

                InsertMenu(hMenu, indexMenu++, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);
                idCmd++;

                // See Q214477 PRB: Duplicate Menu Items In the File Menu For a Shell Context Menu Extension for
                // the reason why we must use InsertMenuItem for the sub-menu.
                MENUITEMINFO mii = { 0 };
                mii.cbSize = sizeof mii;
                mii.fMask = MIIM_SUBMENU | MIIM_FTYPE | MIIM_STRING | MIIM_ID;
                mii.wID = idCmd++;
                mii.fType = MFT_STRING;
                mii.dwTypeData = (TCHAR *)gszAxCryptExternalName;
                mii.cch = (UINT)_tcslen((TCHAR *)gszAxCryptExternalName) + 1;
                mii.fState = MFS_ENABLED;
                mii.hSubMenu = m_hMenu;

                InsertMenuItem(hMenu, indexMenu++, TRUE, &mii);

                // Show a nice little bitmap alongside the Ax Crypt menu selection
                if (ghBitmap == NULL) {
					ghBitmap = LoadBitmap(ghInstance, MAKEINTRESOURCE(IDB_AXCRYPT));
                    CAssert(ghBitmap != NULL).Sys(MSG_SYSTEM_CALL, _T("CShellExt::QueryContextMenu() [LoadBitmap()]")).Throw();
				}
				SetMenuItemBitmaps(hMenu, indexMenu - 1, MF_BYPOSITION, ghBitmap, ghBitmap);

                InsertMenu(hMenu, indexMenu++, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);
	            idCmd++;

                if (m_pSelection->ShowEncryptMenu()) {
                    bool fMany = m_pSelection->ItemsSelected() > 1;
                    bool fFolder = m_pSelection->SelectionIsOneFolder() == TRUE;
                    bool fFile = m_pSelection->SelectionIsOneFile() == TRUE;
                    if (fMany || fFolder || fFile) {
		                SetVerb(m_Verbs, VERB_ENCRYPTZ, idCmd - idCmdFirst);
                        //HMENU hEncryptMenu = CreatePopupMenu();
                        //InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION | MF_POPUP, (UINT_PTR)hEncryptMenu, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());

                        //CFileName fnAxxDest;
                        //if (fMany) {
                        //    fnAxxDest.SetTitle(_T("*"));
                        //} else {
                        //    fnAxxDest.SetTitle(std::auto_ptr<TCHAR>(m_pSelection->GetTitle()).get());
                        //    fnAxxDest.DashExt();
                        //}
                        //fnAxxDest.AddExt(gszAxCryptFileExt);
                        //InsertMenu(hEncryptMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, fnAxxDest.GetTitle());
                        InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());

                        if (!fDefaultSet && m_pSelection->SelectionIsOneFile()) {
                            fDefaultSet = SetMenuDefaultItem(m_hMenu, idCmd, FALSE);
                        }
		                idCmd++;

                        //CFileName fnExeDest;
                        //if (fMany) {
                        //    fnExeDest.SetTitle(_T("*"));
                        //} else {
                        //    fnExeDest.SetTitle(std::auto_ptr<TCHAR>(m_pSelection->GetTitle()).get());
                        //    if (_tcscmp(fnExeDest.GetExt(), gszAxCryptFileExt) == 0) {
                        //        fnExeDest.DelExt();
                        //    } else {
                        //        fnExeDest.DashExt();
                        //    }
                        //}
                        //fnExeDest.AddExt(_T(".exe"));
                        // Insert encrypt-to-copy variant as well
		                SetVerb(m_Verbs, VERB_ENCRYPTZC, idCmd - idCmdFirst);
                        InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
                        idCmd++;

                        // And the self-encrypt too
						// Build the path of the self extractor to start with, so we can check if we actually have it.
						CFileName fnSfxExe;
						fnSfxExe.SetPath2ExeName(ghInstance).SetTitle((LPTSTR)gszAxCryptSfxName);
						if (GetFileAttributes(fnSfxExe.Get()) != INVALID_FILE_ATTRIBUTES) {
							SetVerb(m_Verbs, VERB_SFXENCDEF, idCmd - idCmdFirst);
							InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
							//InsertMenu(hEncryptMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, fnExeDest.GetTitle());
							idCmd++;
						}

		                //SetVerb(m_Verbs, VERB_SFXENCNAME, idCmd - idCmdFirst);
                        //InsertMenu(hEncryptMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, _T(".exe ..."));
		                //idCmd++;
                        fAnyFileOp = TRUE;
                    }
	            }

                if (m_pSelection->ShowDecryptMenu()) {
		            SetVerb(m_Verbs, VERB_DECRYPT, idCmd - idCmdFirst);
		            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
			        if (!fDefaultSet && m_pSelection->SelectionIsOneFile()) fDefaultSet = SetMenuDefaultItem(m_hMenu, idCmd, FALSE);
                    idCmd++;
                    fAnyFileOp = TRUE;
	            }

                if (m_pSelection->ShowOpenMenu()) {
		            SetVerb(m_Verbs, VERB_OPEN, idCmd - idCmdFirst);
		            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
			        if (!fDefaultSet && m_pSelection->SelectionIsOneFile()) fDefaultSet = SetMenuDefaultItem(m_hMenu, idCmd, FALSE);
		            idCmd++;
                    fAnyFileOp = TRUE;
                }

                if (m_pSelection->ShowRenameMenu()) {
		            SetVerb(m_Verbs, VERB_RENAME, idCmd - idCmdFirst);
		            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
		            idCmd++;
                    fAnyFileOp = TRUE;
                }

                if (m_pSelection->ShowBruteForceMenu()) {
                    SetVerb(m_Verbs, VERB_BRUTEFORCE, idCmd - idCmdFirst);
		            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
		            idCmd++;
                    fAnyFileOp = TRUE;
                }

                if (m_pSelection->ShowHexCopyMenu()) {
                    SetVerb(m_Verbs, VERB_HEXCOPY, idCmd - idCmdFirst);
		            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
		            idCmd++;
                    fAnyFileOp = TRUE;
                }

                // Insert a separator if necessary after file operations before utility group
                if (fAnyFileOp) {
                    InsertMenu(m_hMenu, -1, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);
                }

                SetVerb(m_Verbs, VERB_CLEARKEYS, idCmd - idCmdFirst);
	            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                if (m_pSelection->ShowMakeKeyFileMenu()) {
                    // include the Make Key File command.
                    SetVerb(m_Verbs, VERB_KEYFILE, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                if (m_pSelection->ShowWipeMenu()) {
                    InsertMenu(m_hMenu, -1, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);

	                SetVerb(m_Verbs, VERB_WIPE, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                InsertMenu(m_hMenu, -1, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);

                if (m_pSelection->ShowNotifyMeMenu()) {
                    SetVerb(m_Verbs, VERB_NOTIFYME, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                if (m_pSelection->ShowDocsMenu()) {
                    SetVerb(m_Verbs, VERB_DOCS, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                if (m_pSelection->ShowBugReportMenu()) {
                    SetVerb(m_Verbs, VERB_BUGREPORT, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                if (m_pSelection->ShowActivationMenu()) {
                    SetVerb(m_Verbs, VERB_LICENSEMGR, idCmd - idCmdFirst);
	                InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	                idCmd++;
                }

                SetVerb(m_Verbs, VERB_ABOUT, idCmd - idCmdFirst);
	            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

	            HMENU hLanguageSubMenu = CreatePopupMenu();

                // See Q214477 PRB: Duplicate Menu Items In the File Menu For a Shell Context Menu Extension for
                // the reason why we must use InsertMenuItem for the sub-menu.
                UINT langaugeMenuId = idCmd++;

                CMessage languageMenuText;

                MENUITEMINFO mii2 = { 0 };
                mii2.cbSize = sizeof mii2;
                mii2.fMask = MIIM_SUBMENU | MIIM_FTYPE | MIIM_STRING | MIIM_ID;
                mii2.wID = idCmd++;
                mii2.fType = MFT_STRING;
                mii2.dwTypeData = languageMenuText.AppMsg(INF_MENU_LANGUAGE).GetMsg();
                mii2.cch = (UINT)_tcslen(mii2.dwTypeData) + 1;
                mii2.fState = MFS_ENABLED;
                mii2.hSubMenu = hLanguageSubMenu;

                InsertMenuItem(m_hMenu, langaugeMenuId, TRUE, &mii2);

                SetVerb(m_Verbs, VERB_ENGLISH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_DANISH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_GERMAN, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_DUTCH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_HUNGARIAN, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_SPANISH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_FRENCH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_ITALIAN, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_NORWEGIAN, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_SWEDISH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_BRAZILPORTUGUESE, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_POLISH, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

                SetVerb(m_Verbs, VERB_RUSSIAN, idCmd - idCmdFirst);
	            InsertMenu(hLanguageSubMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;

#ifdef _DEBUG
                SetVerb(m_Verbs, VERB_DEBUG, idCmd - idCmdFirst);
	            InsertMenu(m_hMenu, -1, MF_STRING | MF_BYPOSITION, idCmd, CMessage().AppMsg(GetMenuMsgId(m_Verbs, idCmd - idCmdFirst)).GetMsg());
	            idCmd++;
#endif
            } catch (TAssert utErr) {
	            utErr.Show();
	            return (HRESULT)(MAKE_SCODE(SEVERITY_SUCCESS, 0, 0));
            }
        }
    } catch (TAssert utErr) {
        utErr.Show();
    }
	// Make the next index in the menu the success resultcode from this method.
	return (HRESULT)(MAKE_SCODE(SEVERITY_SUCCESS, 0, (WORD)(idCmd - idCmdFirst)));
}
//
//	Carries out the command associated with a context menu item.
//
//	Returns NOERROR if successful, or an OLE-defined error code otherwise.
//	lpici
//		Address of a CMINVOKECOMMANDINFO structure containing information
//		about the command.
//
//	The shell calls this method when the user chooses a command that the
//	handler added to a context menu. This method may also be called by an
//	application without any corresponding user action
//
STDMETHODIMP
CShellExt::InvokeCommand(LPCMINVOKECOMMANDINFO lpici) {
    HRESULT hRes = S_OK;
	// if we are called by the shell, invoke the right action depending
	// on which menu item that was selected.
    char *szVerb = NULL;

    try {
        pfCmdHandlerT pfCmdHandler = NULL;
        // See comment at function. 2005-04-03 /SS if (lpici->hwnd) m_pSelection->SetActiveShellView(lpici->hwnd);

        // It appears that the parent can be NULL in some cases, and it also appears that at least in some cases in Vista
        // you can get a non-null, but according to IsWindow() invalid handle here. See Sourceforge Bug 2956965
		if (m_pSelection->m_hShellFolderWnd == NULL) {
            if (lpici->hwnd != NULL && IsWindow(lpici->hwnd)) {
                m_pSelection->m_hShellFolderWnd = lpici->hwnd;
            }
		}

	    // If extended structure (why make this so hard???)...
	    if (lpici->cbSize == sizeof CMINVOKECOMMANDINFOEX &&
		    // ...and if Unicode...
		    (lpici->fMask & CMIC_MASK_UNICODE) &&
			    // ...and a verb, not a cmd...
			HIWORD(((LPCMINVOKECOMMANDINFOEX)lpici)->lpVerbW)) {
		    // ... then Do Unicode based verb look-up
		    int iLen = WideCharToMultiByte(CP_ACP, 0, ((LPCMINVOKECOMMANDINFOEX)lpici)->lpVerbW, -1, NULL, 0, NULL, NULL);
		    // Not generic here!

		    szVerb = new char[iLen];
            ASSPTR(szVerb);

		    (void)WideCharToMultiByte(CP_ACP, 0, ((LPCMINVOKECOMMANDINFOEX)lpici)->lpVerbW, -1, szVerb, iLen, NULL, NULL);
            pfCmdHandler = DoVerbByVerb(m_Verbs, szVerb);
        } else if (HIWORD(lpici->lpVerb)) {
            // Do Ansi based verb look-up
            pfCmdHandler = DoVerbByVerb(m_Verbs, lpici->lpVerb);
	    } else {
            pfCmdHandler = DoVerbByCmd(m_Verbs, LOWORD(lpici->lpVerb));
	    }
        if (pfCmdHandler == NULL) {
            // It wasn't one of our commands.
            hRes = E_FAIL;
        } else {
            DWORD dwThreadId;
            HANDLE hThread;
            AddRef();
            m_pfCmdHandler = pfCmdHandler;

            typedef unsigned (__stdcall *PTHREAD_START)(void *);
            hThread = (HANDLE)_beginthreadex(NULL, 0, (PTHREAD_START)CommandThread, this, 0, (unsigned *)&dwThreadId);
            CAssert(hThread != NULL).Sys(MSG_SYSTEM_CALL, _T("CShellExt::InvokeCommand [CreateThread]")).Throw();
        }
    } catch (TAssert utErr) {
        utErr.Show();
        hRes = E_INVALIDARG;
    }
    if (szVerb != NULL) delete szVerb;
	return hRes;
}
//
//	Retrieves the language-independent command string or the
//	Help text for a context menu item.
//
//	Returns NOERROR if successful, or an OLE-defined error code otherwise.
//
//	idCmd
//		Menu item identifier offset.
//	uFlags
//		Flags specifying the information to retrieve. This can be one of
//		the following values:
//			GCS_HELPTEXT	Returns the Help text for the menu item.
//			GCS_VALIDATE	Validates that the menu item exists.
//			GCS_VERB		Returns the language-independent command
//							name for the menu item.
//	pwReserved
//		Reserved. Applications must specify NULL when calling this method,
//		and handlers must ignore this parameter when called.
//	pszName
//		Address of the buffer to receive the null-terminated string
//		being retrieved.
//	cchMax
//		Size of the buffer to receive the null-terminated string.
//
//	The language-independent command name can be passed to the
//	IContextMenu::InvokeCommand method to activate a command by an application.
//
//	The Help text is a description that Windows Explorer displays in its status bar;
//	it should be reasonably short (under 40 characters).
//
STDMETHODIMP
CShellExt::GetCommandString(UINT_PTR idCmd,	UINT uFlags, UINT *pwReserved, LPSTR pszName, UINT cchMax) {
        try {
	        if (!IsValidCmd(m_Verbs, idCmd)) {
		        return NOERROR;
	        }
	        switch (uFlags) {
	        case GCS_HELPTEXTA:
                lstrcpynA(pszName, axpl::t2s((TCHAR *)CMessage().AppMsg(GetVerbByCmd(m_Verbs, idCmd)->dwHlp).GetMsg()).c_str(), cchMax);
		        break;
	        case GCS_HELPTEXTW: {
			        CMessage utMsg;
			        utMsg.AppMsg(GetVerbByCmd(m_Verbs, idCmd)->dwHlp);
                    lstrcpynW((LPWSTR)pszName, axpl::t2ws((TCHAR *)utMsg.GetMsg()).c_str(), cchMax);
		        }
		        break;
	        case GCS_VERBA:
		        lstrcpynA(pszName, GetVerbByCmd(m_Verbs, idCmd)->szVerb, cchMax);
		        break;
	        case GCS_VERBW: {
                    WCHAR *wszMsg = CopySzWz(GetVerbByCmd(m_Verbs, idCmd)->szVerb);
		            lstrcpynW((LPWSTR)pszName, wszMsg, cchMax);
		            delete wszMsg;
	            }
            }
        } catch (TAssert utErr) {
            utErr.Show();
        }
	return NOERROR;
}
//
//	Init verb-command id association
//
void
CShellExt::InitVerbs(SVerbs *pVerbs) {
	while (pVerbs->szVerb[0]) {
		pVerbs->iCmd = -1;
		pVerbs++;
	}
}
//
//	Set verb-command id association
//
void
CShellExt::SetVerb(SVerbs *pVerbs, char *szVerb, int iCmd) {
	while (pVerbs->szVerb[0]) {
		if (strcmp(pVerbs->szVerb, szVerb) ==0) {
			pVerbs->iCmd = iCmd;
			return;
		}
		pVerbs++;
	}
}

BOOL
CShellExt::IsValidCmd(SVerbs *pVerbs, UINT_PTR iCmd) {
	while (pVerbs->szVerb[0]) {
		if (pVerbs->iCmd == iCmd) {
			return TRUE;
		}
		pVerbs++;
	}
	return FALSE;
}

DWORD
CShellExt::GetMenuMsgId(SVerbs *pVerbs, int iCmd) {
	while (pVerbs->szVerb[0]) {
		if (pVerbs->iCmd == iCmd) {
			return pVerbs->dwCmd;
		}
		pVerbs++;
	}
	return INF_MENU_ERROR;
}

CShellExt::SVerbs *
CShellExt::GetVerbByCmd(SVerbs *pVerbs, UINT_PTR iCmd) {
	while (pVerbs->szVerb[0]) {
		if (pVerbs->iCmd == iCmd) {
			return pVerbs;
		}
		pVerbs++;
	}
	return pVerbs;
}
//
//	Execute by command id association
//
pfCmdHandlerT
CShellExt::DoVerbByCmd(SVerbs *pVerbs, int iCmd) {
	while (pVerbs->szVerb[0]) {
		if (pVerbs->iCmd == iCmd) {
			return pVerbs->pfCmdHandler;
		}
		pVerbs++;
	}
	return NULL;
}
//
//	Execute by verb association
//
pfCmdHandlerT
CShellExt::DoVerbByVerb(SVerbs *pVerbs, const char *szVerb) {
	while (pVerbs->szVerb[0]) {
		if (strcmp(pVerbs->szVerb, szVerb) == 0) {
			return pVerbs->pfCmdHandler;
		}
		pVerbs++;
	}
	return NULL;
}
//
//  Called from the worker thread, this is the function that actually does
//  the work. We need the iteration, as the CreateThread cannot call a member
//  function directly.
//
void
CShellExt::IterateSelection() {
    // Ensure that OLE does not unload our DLL prematurely!
    //InterlockedIncrement(&glRefThisDLL);

    // Assign a batch-id to this operation, unless it's just a single file, in which case we
    // don't use a batch-id at all.
    bool fIsOneFile = (m_pSelection->SelectionIsOneFile() == TRUE);
    SetBatch(fIsOneFile ? 0 : -1);

    // Iterate over the selection, giving call-back function and 'this'
    m_pSelection->IterateAll(this, m_pfCmdHandler);

    // Clear batch keys - if used!
    // Quick and _very_ dirty fix to handle clear keys in this case too...
    if (!fIsOneFile || (m_pfCmdHandler == &CShellExt::DoClearKeys)) {
        CallAxCrypt(NULL, _T(" -t"));
    }

    // Decrement our own reference counter.
    Release();
    // Also release the hold on the DLL it-self.
    //InterlockedDecrement(&glRefThisDLL);
}
//
//  Just an intermediary for the worker thread.
//
/*static*/ DWORD WINAPI
CShellExt::CommandThread(LPVOID lParam) {
    try {
        // We must initialize COM for each thread...
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        ((CShellExt *)lParam)->IterateSelection();
    } catch (TAssert utErr) {
        utErr.Show();
    }
    return 0;
}

DWORD
CShellExt::DoEncryptCompress(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (!IsEncrypted(pShellFolder, pidlFile) && !IsFolder(pShellFolder, pidlFile)) {
            return DoAxCrypt(hProgressWnd, _T(" -z "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
	return 0;
}

DWORD
CShellExt::DoEncryptCompressCopy(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (!IsEncrypted(pShellFolder, pidlFile) && !IsFolder(pShellFolder, pidlFile)) {
            return DoAxCrypt(hProgressWnd, _T(" -c -z "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
	return 0;
}

/// Self-extracting encryption one-by-one to default name.
DWORD
CShellExt::DoSfxEncDef(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (IsFile(pShellFolder, pidlFile)) {
            return DoAxCrypt(hProgressWnd, _T(" -J "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
    return 0;
}

/// Self-extracting encryption many-to-one to user defined name.
DWORD
CShellExt::DoSfxEncName(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_FOLDER:
    case IT_END_FOLDER:
    case IT_FILE:
    default:
        MessageBox(NULL, _T("DoSfxEncName"), AXPRODUCTFILENAME, MB_OK);
        break;
    }
    return 0;
}

DWORD
CShellExt::DoDecrypt(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (IsEncrypted(pShellFolder, pidlFile)) {
	        return DoAxCrypt(hProgressWnd, _T(" -d "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
	return 0;
}

DWORD
CShellExt::DoWipe(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    // We use the parameter for this run to keep track of if the user in Ax Crypt has selected the 'Yes to all'
    // option, so we don't have to ask all the time...
    enum {ASKFOREACH, YESTOALL};
    DWORD dwReturn = 0;

    switch (eventId) {
    case IT_INIT:
        if (ppParam) {
            *ppParam = new CParam;
            ASSPTR(*ppParam);

            (**ppParam).m_param = ASKFOREACH;
        }
        break;
    case IT_END:
        break;
    case IT_END_FOLDER:
        if (IsFolder(pShellFolder, pidlFile)) {
            axpl::ttstring sFolder = GetPath(pShellFolder, pidlFile);
            if (RemoveDirectory(sFolder.c_str())) {
                // Signal caller that a folder was deleted. This is not an error.
                dwReturn = INF_IT_FOLDER_DEL;
            } else {
                // Accept not-empty directory as an accepted non-error
                if ((dwReturn = GetLastError()) == ERROR_DIR_NOT_EMPTY) {
                    dwReturn = 0;
                }
            }
        }
        break;
    case IT_FOLDER:
        if (IsFolder(pShellFolder, pidlFile)) {
            // If we're asking for each still
            if (ppParam && *ppParam && ((**ppParam).m_param == ASKFOREACH)) {
                // Wipe of a folder does nothing, just asks the confirmation question.
                dwReturn = DoAxCrypt(hProgressWnd, _T(" -w "), pShellFolder, pidlFile);
                if (ppParam && *ppParam && (dwReturn == INF_YESALL)) {
                    (**ppParam).m_param = YESTOALL;
                    dwReturn = 0;
                }
            }
            // If it's a folder, start asking again.
            //if (ppParam && *ppParam) {
            //    (**ppParam).m_param = ASKFOREACH;
            //}
        }
        break;
    case IT_FILE:
        if (IsFile(pShellFolder, pidlFile)) {
            if (ppParam && *ppParam && ((**ppParam).m_param == YESTOALL)) {
                dwReturn = DoAxCrypt(hProgressWnd, _T(" -s "), pShellFolder, pidlFile);
            } else {
                dwReturn = DoAxCrypt(hProgressWnd, _T(" -w "), pShellFolder, pidlFile);
                if (ppParam && *ppParam && (dwReturn == INF_YESALL)) {
                    (**ppParam).m_param = YESTOALL;
                    dwReturn = 0;
                }
            }
        }
        break;
    default:
        break;
    }
	return dwReturn;
}

DWORD
CShellExt::DoOpen(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (IsEncrypted(pShellFolder, pidlFile)) {
	        return DoAxCrypt(hProgressWnd, _T(" "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
    return 0;
}

DWORD
CShellExt::DoDebug(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
        if (MessageBox(NULL, _T("Initalizing iteration, continue?"), AXPRODUCTFILENAME _T(" Shell Extension Debug"), MB_YESNO) == IDYES) {
            return 0;
        } else {
            return WRN_CANCEL;
        }
        break;
    case IT_END:
    case IT_FOLDER:
    case IT_END_FOLDER:
    case IT_FILE:
    default:
        MessageBox(NULL, GetPath(pShellFolder, pidlFile).c_str(), AXPRODUCTFILENAME _T(" Shell Extension Debug"), MB_OK);
        break;
    }
    return 0;
}

DWORD
CShellExt::DoClearKeys(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
        // Reset the batch-number to zero, then abort. This causes nothing to happen in
        // the iteration, but the end-batch will still be executed, now with value '0'...
        SetBatch(0);
        break;
    case IT_END:
    case IT_FOLDER:
    case IT_END_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return WRN_CANCEL;
}

DWORD
CShellExt::DoRename(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
        break;
    case IT_FOLDER:
    case IT_FILE:
        if (IsEncrypted(pShellFolder, pidlFile)) {
	        return DoAxCrypt(hProgressWnd, _T(" -h "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
	return 0;
}

/// \brief Simple helper to build the actual command for 'Do Key File'
DWORD
CShellExt::DoKeyFileHelper(HWND hProgressWnd, const TCHAR *szFolder) {
    bool fNeedsBackslash = false;
    if (szFolder[0]) {
        fNeedsBackslash = szFolder[_tcslen(szFolder) - 1] == _T('\\');
    }
    CStrPtr szCmd = CStrPtr(_T(" -K \"")) + CStrPtr(szFolder)
                                      + CStrPtr(fNeedsBackslash ? _T("\\") : _T(""))
                                      + CStrPtr(_T("\""));
    // Always return non-zero to terminate iteration immediately, as we
    // do not want to do this for every file in a folder.
    return CallAxCrypt(hProgressWnd, szCmd) || INF_NOERROR;
}

DWORD
CShellExt::DoKeyFile(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END_FOLDER:
        break;
    case IT_FILE:
    case IT_FOLDER:
        // If we're called with a file, we use that file's directory instead.
        if (IsFile(pShellFolder, pidlFile)) {
            axpl::ttstring sFolder = GetPath(pShellFolder, pidlFile);

            CAutoArray<wchar_t> szFolder(new wchar_t[sFolder.length() + 1]);
            wcscpy_s(szFolder.Get(), sFolder.length() + 1, sFolder.c_str());
            PathRemoveFileSpec(szFolder.Get());
            return DoKeyFileHelper(hProgressWnd, szFolder.Get());
        } else if (IsFolder(pShellFolder, pidlFile)) {
            axpl::ttstring sFolder = GetPath(pShellFolder, pidlFile);
            return DoKeyFileHelper(hProgressWnd, sFolder.c_str());
        }
        // Fall through...
    case IT_END:
        {
            // ...if we get here we're either falling through, or we're reaching end without
            // anything else happening, so then we also want to do it in cur dir.
	        // Get length of the buffer required, and then put the current directory there.
	        DWORD dwLen = GetCurrentDirectory(0, NULL);
	        CAssert(dwLen).Sys(MSG_SYSTEM_CALL, _T("CShellExt::DoKeyFile() [GetCurrentDirectory(0)]")).Throw();
            std::auto_ptr<_TCHAR> szCurDir(new _TCHAR[dwLen]);
            ASSPTR(szCurDir.get());

            CAssert(GetCurrentDirectory(dwLen, szCurDir.get())).Sys(MSG_SYSTEM_CALL, _T("CShellExt::DoKeyFile() [GetCurrentDirectory(szCurDir)]")).Throw();

            return DoKeyFileHelper(hProgressWnd, szCurDir.get());
        }
    default:
        break;
    }
    return 0;
}

DWORD
CShellExt::DoNotifyMe(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT: {
        std::auto_ptr<TCHAR> szNotifyName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValAfterNotifyName).GetSz(_T("")));
        if (szNotifyName.get() && szNotifyName.get()[0]) {
            CFileName pathToNotify;
            pathToNotify.SetPath2ExeName(ghInstance).SetTitle(szNotifyName.get());
            if (GetFileAttributes(pathToNotify.Get()) != INVALID_FILE_ATTRIBUTES) {
                // Launch the Notify program
                if ((LONG_PTR)ShellExecute(NULL, _T("open"), pathToNotify.Get(), NULL, NULL, SW_SHOWNORMAL) > 32) {
                    return INF_NOERROR;
                } else {
                    return ERR_UNSPECIFIED;
                }
            }
        }
        return ERR_UNSPECIFIED;
        break;
    }
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return 0;
}

DWORD
CShellExt::DoDocs(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT: {
        std::auto_ptr<TCHAR> szDocumentationName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDocumentationName).GetSz(_T("")));
        if (szDocumentationName.get()[0]) {
            // Launch the Docs program
            if ((LONG_PTR)ShellExecute(NULL, _T("open"), szDocumentationName.get(), NULL, NULL, SW_SHOWNORMAL) > 32) {
                return INF_NOERROR;
            } else {
                return ERR_UNSPECIFIED;
            }
        }
        return ERR_UNSPECIFIED;
        break;
    }
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return 0;
}

/// \brief Helper for About-box, formats strings of info about component files
static void
aboutOneLine(HWND hwndListBox, const _TCHAR *szFileName, CVersion& ver, DWORD& dwMaxExtent) {
    HDC hDCListBox;
    HFONT hFontOld, hFontNew;
    TEXTMETRIC tm;
    SIZE size;
    std::auto_ptr<_TCHAR> sz(new _TCHAR[1024]);

    hDCListBox = GetDC(hwndListBox);
    hFontNew = (HFONT)SendMessage(hwndListBox, WM_GETFONT, NULL, NULL);
    hFontOld = (HFONT)SelectObject(hDCListBox, hFontNew);
    GetTextMetrics(hDCListBox, (LPTEXTMETRIC)&tm);

    wsprintf(sz.get(), _T("%s  [%s]: %s, %s"), szFileName, std::auto_ptr<const _TCHAR>(ver.FileVersionString()).get(), ver.FileDescription(), ver.LegalCopyright());
    GetTextExtentPoint32(hDCListBox, sz.get(), (int)_tcslen(sz.get()), &size);
    DWORD dwExtent = size.cx +  + tm.tmAveCharWidth;
    if (dwExtent > dwMaxExtent) {
        SendMessage(hwndListBox, LB_SETHORIZONTALEXTENT, dwMaxExtent = dwExtent, 0);
    }
    SendMessage(hwndListBox, LB_ADDSTRING, 0, (LPARAM)sz.get());

    SelectObject(hDCListBox, hFontOld);
    ReleaseDC(hwndListBox, hDCListBox);
}

/// \brief Dialog procedure for about box
/// \param hwndDlg Handle to dialog box
/// \param uMsg Message
/// \param wParam First message parameter
/// \param lParam Second message parameter
/// \return TRUE if...
INT_PTR CALLBACK
AboutDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    CFileName fnPath;
    std::auto_ptr<_TCHAR> sz;

	switch (uMsg) {
    case WM_INITDIALOG: {
        DWORD dwMaxExtent = 0;
        CenterWindow(hwndDlg, true);

        std::auto_ptr<_TCHAR> szSprintfBuf(new _TCHAR[1024]);
        CVersion verAxCryptDll(ghInstance);

        // Setup Ax Crypt main program version info.
        fnPath.SetPath2ExeName(ghInstance).SetTitle(gszAxCryptProgramName);
        CVersion verAxCrypt(fnPath.Get());

        // Generate the version string text for Ax Crypt
        aboutOneLine(GetDlgItem(hwndDlg, IDC_LISTABOUT), fnPath.GetTitle(), verAxCrypt, dwMaxExtent);

        // Generate the version string text for the Shell Extension
        fnPath.SetPath2ExeName(ghInstance);
        aboutOneLine(GetDlgItem(hwndDlg, IDC_LISTABOUT), fnPath.GetTitle(), verAxCryptDll, dwMaxExtent);

        // Generate the version string text for the messages dll
        fnPath.SetPath2ExeName(ghInstance).SetTitle((LPTSTR)gszAxCryptMessageDLL);
        CVersion verAxCryptM(fnPath.Get());
        aboutOneLine(GetDlgItem(hwndDlg, IDC_LISTABOUT), fnPath.GetTitle(), verAxCryptM, dwMaxExtent);

        CMessage msg;

        SetDlgItemText(hwndDlg, IDC_INF_ABOUT, msg.Wrap(0).AppMsg(INF_ABOUT, verAxCrypt.LegalCopyright()).GetMsg());

        // Set window title 'About Ax Crypt'
        msg.AppMsg(INF_MENU_ABOUT);
        wsprintf(szSprintfBuf.get(), _T("%s %s"), msg.GetMsg(), verAxCrypt.String());
        SetWindowText(hwndDlg, szSprintfBuf.get());

        // Set Button text of Notify and hide it if we don't have the program to go with it.
        msg.AppMsg(INF_MENU_NOTIFYME);
        SetDlgItemText(hwndDlg, IDC_BTN_NOTIFY, msg.GetMsg());
        sz = std::auto_ptr<_TCHAR>(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValAfterNotifyName).GetSz(_T("")));
        if (sz.get() && sz.get()[0] && (fnPath.SetPath2ExeName(ghInstance).SetTitle(sz.get()), GetFileAttributes(fnPath.Get()) != INVALID_FILE_ATTRIBUTES)) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_NOTIFY), TRUE);
        } else {
            ShowWindow(GetDlgItem(hwndDlg, IDC_BTN_NOTIFY), SW_HIDE);
        }

        // Set button text for Documentation, and hide it if we don't have the file to go with it.
        std::auto_ptr<TCHAR> szDocumentationName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDocumentationName).GetSz(_T("")));
        msg.AppMsg(INF_MENU_DOCS);
        SetDlgItemText(hwndDlg, IDC_BTN_DOCS, msg.GetMsg());
        if (szDocumentationName.get() && szDocumentationName.get()[0]) {
            EnableWindow(GetDlgItem(hwndDlg, IDC_BTN_DOCS), TRUE);
        } else {
            ShowWindow(GetDlgItem(hwndDlg, IDC_BTN_DOCS), SW_HIDE);
        }

        // Generate the version string text for AxDecrypt
        if (gszAxCryptSfxName && gszAxCryptSfxName[0]) {
            CFileName fnAxDecrypt;
            fnAxDecrypt.SetPath2ExeName(ghInstance).SetTitle((LPTSTR)gszAxCryptSfxName);
            if (GetFileAttributes(fnAxDecrypt.Get()) != INVALID_FILE_ATTRIBUTES) {
                CVersion verAxDecrypt(fnAxDecrypt.Get());

                aboutOneLine(GetDlgItem(hwndDlg, IDC_LISTABOUT), fnAxDecrypt.GetTitle(), verAxDecrypt, dwMaxExtent);
            }
        }
        break;
    }
	case WM_COMMAND:
	{
        switch (wParam) {
        case IDC_BTN_DOCS:
            {
                std::auto_ptr<TCHAR> szDocumentationName(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDocumentationName).GetSz(_T("")));
                if (szDocumentationName.get()[0]) {
                    (void)ShellExecute(NULL, _T("open"), szDocumentationName.get(), NULL, NULL, SW_SHOWNORMAL);
                }
            }
            break;
        case IDC_BTN_NOTIFY:
            sz = std::auto_ptr<TCHAR>(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValAfterNotifyName).GetSz(_T("")));
            if (sz.get() && sz.get()[0]) {
                fnPath.SetPath2ExeName(ghInstance).SetTitle(sz.get());
                if (GetFileAttributes(fnPath.Get()) != INVALID_FILE_ATTRIBUTES) {
                    // Launch the Notify program
                    (void)ShellExecute(NULL, _T("open"), fnPath.Get(), NULL, NULL, SW_SHOWNORMAL);
                }
            }
            break;
		case IDOK:
			EndDialog(hwndDlg, TRUE);
			break;
		case IDCANCEL:
			EndDialog(hwndDlg, FALSE);
			break;
		}
		return TRUE;
    }
	default:
        break;
    }
	return FALSE;
}

/// \brief Display an about menu
DWORD
CShellExt::DoAbout(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
        switch (DialogBoxParam(ghInstance, MAKEINTRESOURCE(IDD_ABOUT), NULL, AboutDlgProc, (LPARAM)0)) {
	    case IDOK:
            break;
        case IDCANCEL:
            break;
	    default:
            break;
	    }
        return INF_NOERROR;
        break;
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return INF_NOERROR;
}

/// \brief Launch whatever is given in the registry setting for the bugreport
DWORD
CShellExt::DoBugReport(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    std::auto_ptr<TCHAR> szBugReport(CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValBugReport).GetSz(_T("")));
    switch (eventId) {
    case IT_INIT:
        // Launch the URL or whatever from the registry
        if (szBugReport.get()[0]) {
            // Setup Ax Crypt main program version info.
            CFileName fnPath;
            fnPath.SetPath2ExeName(ghInstance).SetTitle(gszAxCryptProgramName);
            CVersion verAxCrypt(fnPath.Get());

            if (MessageBox(NULL, CMessage().AppMsg(HLP_MENU_BUGREPORT).GetMsg(), verAxCrypt.String(), MB_OKCANCEL|MB_ICONINFORMATION) == IDOK) {
                // We just launch - don't really care about the result.
                ShellExecute(NULL, _T("open"), szBugReport.get(), NULL, NULL, SW_SHOWNORMAL);
            }
        }
        return INF_NOERROR;
        break;
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return INF_NOERROR;
}

/// \brief Open the license manager window
DWORD
CShellExt::DoLicenseMgr(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
        // Do the command and always end the iteration, if any.
	    return CallAxCrypt(hProgressWnd, _T(" -l")) || INF_NOERROR;
        break;
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return INF_NOERROR;
}

/// \brief Change the language selection
DWORD
DoLanguage(itEventT eventId, DWORD languageId) {
    switch (eventId) {
    case IT_INIT:
        // Do the command and always end the iteration, if any.
        CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValDefaultLanguageId).SetDword(languageId);
        break;
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
    return INF_NOERROR;
}

DWORD
CShellExt::DoEnglish(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1033);
}

DWORD
CShellExt::DoDanish(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1030);
}

DWORD
CShellExt::DoGerman(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1031);
}

DWORD
CShellExt::DoDutch(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1043);
}

DWORD
CShellExt::DoHungarian(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1038);
}

DWORD
CShellExt::DoSpanish(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1034);
}

DWORD
CShellExt::DoFrench(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1036);
}

DWORD
CShellExt::DoItalian(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1040);
}

DWORD
CShellExt::DoNorwegian(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1044);
}

DWORD
CShellExt::DoSwedish(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1053);
}

DWORD
CShellExt::DoBrazilPortuguese(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1046);
}

DWORD
CShellExt::DoPolish(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1045);
}

DWORD
CShellExt::DoRussian(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    return DoLanguage(eventId, 1049);
}

static TCHAR szBruteForce[80]; // receives checkpoint/starting value

static BOOL CALLBACK BruteForceProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG:
            {
                TCHAR *szCheckPoint =  CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValBruteForceCheck).GetSz(_T("0:"));
                _tcsncpy_s(szBruteForce, sizeof szBruteForce / sizeof szBruteForce[0], szCheckPoint, sizeof szBruteForce / sizeof szBruteForce[0] - 1);
                delete szCheckPoint;
                SetDlgItemText(hwndDlg, IDC_BRUTEFORCE, szBruteForce);
            }
            return TRUE;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                    if (!GetDlgItemText(hwndDlg, IDC_BRUTEFORCE, szBruteForce, sizeof szBruteForce))  {
                         szBruteForce[0] = _T('\0');
                    }
                    // Fall through.
                 case IDCANCEL:
                    EndDialog(hwndDlg, wParam);
                    return TRUE;
            }
    }
    return FALSE;
}

DWORD
CShellExt::DoBruteForce(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
        break;
    case IT_FILE:
        if (IsEncrypted(pShellFolder, pidlFile)) {
            if (DialogBox(ghInstance, MAKEINTRESOURCE(IDD_BRUTEFORCE), NULL, (DLGPROC)(BruteForceProc))) {
                TCHAR szCmd[sizeof szBruteForce + 20];
                _stprintf_s(szCmd, sizeof szCmd / sizeof szCmd[0], _T(" -R \"%s\" "), szBruteForce);

                return DoAxCrypt(hProgressWnd, szCmd, pShellFolder, pidlFile);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

DWORD
CShellExt::DoHexCopy(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
        break;
    case IT_FILE:
        if (IsEncrypted(pShellFolder, pidlFile)) {
            // Open the file, read a small amount of data, convert it to hex, and place it on the
            // clipboard.
            const size_t cbBufSiz = 512;
            unsigned char bBuf[cbBufSiz];
            TCHAR szHex[cbBufSiz * 4];
            HANDLE hFile = CreateFile(GetPath(pShellFolder, pidlFile).c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                return GetLastError();
            }
            DWORD cb;
            if (!ReadFile(hFile, bBuf, sizeof bBuf, (DWORD *)&cb, NULL)) {
                CloseHandle(hFile);
                return GetLastError();
            }
            CloseHandle(hFile);
            TCHAR *sz = szHex;
            unsigned char *p = bBuf;
            size_t i = 0;
            const int iPerLine = 16;
            while (i < cb) {
                if (i % iPerLine) {
                    *sz++ = _T(' ');
                }
                TCHAR szN[33+1];        // itoa defines the max to be 33 chars
                _itot_s(*p++ + 256, szN, sizeof szN / sizeof szN[0], 16);
                *sz++ = szN[1];
                *sz++ = szN[2];
                i++;
                if (i == cb || (i % iPerLine == 0)) {
                    *sz++ = _T('\r');
                    *sz++ = _T('\n');
                }
            }
            *sz++ = _T('\0');
            bool fOk = false;
            if (OpenClipboard(hProgressWnd)) {
                if (EmptyClipboard()) {
                    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, sizeof szHex);
                    if (hMem) {
                        LPTSTR szCopy  = (LPTSTR)GlobalLock(hMem);
                        if (szCopy) {
                            _tcscpy_s(szCopy, sizeof szHex / sizeof szHex[0], szHex);
                            GlobalUnlock(hMem);
                            if (SetClipboardData(sizeof szHex[0] == sizeof (wchar_t) ? CF_UNICODETEXT : CF_TEXT, hMem) != NULL) {
                                fOk = true;
                            }
                        }
                    }
                }
                fOk = CloseClipboard() && fOk;
            }

            return fOk ? ERROR_SUCCESS : GetLastError();
        }
        break;
    default:
        break;
    }
    return ERROR_SUCCESS;
}

DWORD
CShellExt::DoNothing(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
    case IT_FILE:
    default:
        break;
    }
	return 0;
}

DWORD
CShellExt::DoEncryptOnly(itEventT eventId, HWND hProgressWnd, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile, CParam **ppParam) {
    switch (eventId) {
    case IT_INIT:
    case IT_END:
    case IT_END_FOLDER:
    case IT_FOLDER:
        break;
    case IT_FILE:
        if (!IsEncrypted(pShellFolder, pidlFile) && !IsFolder(pShellFolder, pidlFile)) {
	        return DoAxCrypt(hProgressWnd, _T(" -e "), pShellFolder, pidlFile);
        }
        break;
    default:
        break;
    }
	return 0;
}
//
//	Actually perform  an action by calling the main process, adding the
//  batch identifier in the process...
//
DWORD
CShellExt::CallAxCrypt(HWND hProgressWnd, LPTSTR szParams) {
    CFileName szPath2Exe;

	szPath2Exe.SetPath2ExeName(ghInstance).SetTitle(gszAxCryptProgramName);
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
    DWORD dwReturn;
    CStrPtr szCmd = CStrPtr(szPath2Exe.GetQuoted()) +
                    CStrPtr(_T(" -b ")) +
                    CStrPtr(GetBatchStr()) +
                    CStrPtr(szParams);
    ZeroMemory(&StartupInfo, sizeof StartupInfo);
	ZeroMemory(&ProcessInformation, sizeof ProcessInformation);
	StartupInfo.cb = sizeof StartupInfo;

    if (!CreateProcess(
		NULL,
		(LPTSTR)szCmd,
		NULL,
		NULL,
		0,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInformation)) {
        CAssert(FALSE).Sys().Show();
        DWORD dwLastError = GetLastError();			// Just for debug, ignore right now.
        return dwLastError;
	}
    // Mark the progress-window with the correct process-ID.
    if (hProgressWnd != NULL) {
        SetWindowLongPtr(hProgressWnd, GWLP_USERDATA, ProcessInformation.dwProcessId);
    }
    ResumeThread(ProcessInformation.hThread);
    DlgMessageWaitForSingleObject(GetParent(hProgressWnd), ProcessInformation.hProcess, INFINITE);

    if (!GetExitCodeProcess(ProcessInformation.hProcess, &dwReturn)) {
        MessageBox(NULL, _T("Could not get exit code"), AXPRODUCTFILENAME _T(" Shell Extension"), MB_OK);
        CMessage().SysMsg(GetLastError()).ShowError();
        return GetLastError();
    }
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    return dwReturn;
}

DWORD
CShellExt::DoAxCrypt(HWND hProgressWnd, LPTSTR szOption, IShellFolder *pShellFolder, LPCITEMIDLIST pidlFile) {
    CStrPtr szCmd = CStrPtr(szOption) + CStrPtr(CFileName(GetPath(pShellFolder, pidlFile).c_str()).GetQuoted());
    return CallAxCrypt(hProgressWnd, szCmd);
}

//
//  Derive a reasonably unique batch id for this operation.
//  Zero is a reserved value meaning all, thus we avoid
//  that one.
//
void
CShellExt::SetBatch(int iBatch) {
    if (iBatch == -1) {
        m_iBatch = (GetTickCount() & 0x7fffffff) | 1;
    } else {
        m_iBatch = iBatch;
    }

    if (m_szBatch != NULL) delete m_szBatch;

    // Calculate the length of the resulting string, in chars, including null.
    int iStrLen = 1, j = m_iBatch;
    do {
        j /= 10;
        iStrLen++;
    } while (j);

    m_szBatch = new TCHAR[iStrLen];
    ASSPTR(m_szBatch);

    (void)_itot_s(m_iBatch, m_szBatch, iStrLen, 10);
}
//
//  Get the current batch id into a dynamically allocated
//  string, and return the pointer. Please do not delete
//  it...
//
LPTSTR
CShellExt::GetBatchStr() {
    return m_szBatch;
}