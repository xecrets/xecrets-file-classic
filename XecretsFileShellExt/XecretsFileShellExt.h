#pragma once
/*
@(#) $Id$

Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
Server or Web Storage of Document Files.

Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

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
ShellExt.h      				Definition of Class Factory and Object for the Xecrets File
Shell Extension.

E-mail							YYYY-MM-DD				Reason
software@axantum.com	    		2001					Initial
2002-07-25              Ver 1.2
*/

#ifndef		STRICT
#define		STRICT
#endif

#ifdef XECRETSFILESHELLEXT_EXPORTS
#define XECRETSFILESHELLEXT_API __declspec(dllexport)
#else
#define XECRETSFILESHELLEXT_API __declspec(dllimport)
#endif

#define		INC_OLE2

#ifndef WINVER
#define WINVER 0x0600           // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600     // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600        // Specifies that the minimum required platform is Internet Explorer 6.0.
#endif

#include <windowsx.h>
#include <shlobj.h>
#include <tchar.h>
#include <commctrl.h>
//
#include "resource.h"

#include "../XecretsFileCommon/Oem.h"
#include "../XecretsFileCommon/Types.h"
#include "../XecretsFileCommon/Utility.h"
#include "../XecretsFileCommon/AxCommon.h"
#include "../XecretsFileCommon/CAssert.h"
#include "XecretsFileTexts.h"

#include "../AxPipe/AxPipe.h"

//
// The class ID of the Xecrets File Shell Extension class.
//
// class id:  1918AECB-5BDB-43D9-83B4-FDD4BEC67E4F
//
//
extern long glRefThisDLL;					// Reference count of this DLL.
extern HINSTANCE ghInstance;				// Handle to this DLL itself.
extern HBITMAP ghBitmap;					// Handle to the menu bit-map
extern IMalloc* gpMalloc;
//
//  Helpers
//
extern void DecrementDllReference();
extern void IncrementDllReference();
//
//	Our very own Class Factory - used and required by the shell
//
class CShellExtClassFactory : public IClassFactory {
protected:
	ULONG m_cRef;
public:
	CShellExtClassFactory();
	virtual ~CShellExtClassFactory();

	// IUnknown
	STDMETHODIMP QueryInterface(REFIID iid, void** ppvObject);
	STDMETHODIMP_(ULONG) AddRef();
	STDMETHODIMP_(ULONG) Release();

	// IClassFactory
	STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject);
	STDMETHODIMP LockServer(BOOL fLock);
};
typedef CShellExtClassFactory* LPCSHELLEXTCLASSFACTORY;
//
//  Parameter class for verbs. Needs a class with a virtual destructor
//  to handle deletion properly by caller.
//
class CParam {
public:
	DWORD m_param;                      // Just a long for generic use.
	CParam() : m_param(0) {}
	virtual ~CParam() {}
};
/// \brief Define the different possible events during an iteration
typedef enum {
	IT_INIT = 1,                            ///< First, before any files event of iteration.
	IT_END,                                 ///< Last, after all files are processed.
	IT_FOLDER,                              ///< Process a folder
	IT_END_FOLDER,                          ///< After processing all files (and folders) in a folder
	IT_FILE,                                ///< Process a file
} itEventT;

//
//	Forward declaration: Cmd Handler function type
//
class CShellExt;
typedef DWORD(CShellExt::* pfCmdHandlerT)(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);

//
//  Support class to handle all interaction with the list of files
//  we get from the Windows Explorer.
//
class CFileObjectList {
public:
	CFileObjectList();
	~CFileObjectList();

	void SetObject(IDataObject* pdobj);
	// void SetActiveShellView(HWND hWnd);

	int ItemsSelected();
	BOOL SelectionIsOneFile();
	BOOL SelectionIsOneFolder();            ///< TRUE if sel is exactly one folder
	BOOL ShowPropertySheet();
	BOOL ShowOpenMenu();
	BOOL ShowEncryptMenu();
	BOOL ShowMakeKeyFileMenu();
	BOOL ShowDecryptMenu();
	BOOL ShowWipeMenu();
	BOOL ShowRenameMenu();
	BOOL ShowBruteForceMenu();
	BOOL ShowHexCopyMenu();
	BOOL ShowReEncryptMenu() { return FALSE; }
	BOOL ShowNotifyMeMenu();
	BOOL ShowDocsMenu();
	BOOL ShowBugReportMenu();
	BOOL ShowActivationMenu();
	LPTSTR GetTitle();                      ///< Get the name of one selected item, or NULL;

	void IterateAll(CShellExt* pShellExt, pfCmdHandlerT pfCmdHandler);

private:
	void InitIteration();
	LPCITEMIDLIST Iterate();
	DWORD IteratePidl(IShellFolder* pShellFolder, LPCITEMIDLIST pidl, CShellExt* pShellExt, pfCmdHandlerT pfCmdHandler, CParam** ppParam);
	void EndIteration();
	void ShellNotify(IShellFolder* pShellFolder, LPCITEMIDLIST pidl, LONG lEvent);

	IShellFolder* m_pDesktopFolder;
	//    IShellBrowser *m_pShellBrowser;
	IDataObject* m_pDataObj;
	IShellFolder* m_pShellFolder;
	LPITEMIDLIST m_pidlShellFolder;
	//    IShellView *m_pShellView;

	CIDA* m_pCIDA;
	STGMEDIUM m_StgMedium;

public:
	HWND m_hShellFolderWnd;
private:
	UINT m_iItemIndex;
	BOOL m_fShellViewHasBeenReset;
	HWND m_hProgressWnd;
};
//
// The shell extension object as such
//
class CShellExt : public IShellExtInit, IContextMenu, IShellPropSheetExt {
public:
	CShellExt();
	virtual ~CShellExt();

	// IUnknown
	STDMETHODIMP QueryInterface(REFIID iid, void** ppvObject);
	STDMETHODIMP_(ULONG) AddRef();
	STDMETHODIMP_(ULONG) Release();

	// IShellExtInit
	STDMETHODIMP Initialize(LPCITEMIDLIST pidlFolder, IDataObject* pdobj, HKEY hkeyProgID);

	// IContextMenu
	STDMETHODIMP QueryContextMenu(HMENU hMenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast, UINT uFlags);
	STDMETHODIMP InvokeCommand(LPCMINVOKECOMMANDINFO lpici);
	STDMETHODIMP GetCommandString(UINT_PTR idCmd, UINT uFlags, UINT* pwReserved, LPSTR pszName, UINT cchMax);

	// IShellPropSheetExt
	STDMETHODIMP AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam);
	STDMETHODIMP ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplaceWith, LPARAM lParam);

private:
	int m_iBatch;               // The batch-id assigned to this operation.
	LPTSTR m_szBatch;           // The string representation of the batch id
	ULONG m_cRef;               // The object reference counter
	HMENU m_hMenu;              // Handle to the context menu, when relevant.
public:
	CFileObjectList* m_pSelection;// The list of selected object,and iteration context etc
	pfCmdHandlerT m_pfCmdHandler;
private:
	//
	//	Verbs list w/commands. Notable: Use explicit ASCII-strings here, we
	//	convert to Unicode when necessary.
	//
	static struct SVerbs {
		char* szVerb;
		DWORD dwCmd;
		DWORD dwHlp;
		int iCmd;
		pfCmdHandlerT pfCmdHandler;
	} m_Verbs[];

	void InitVerbs(SVerbs* pVerbs);
	void SetVerb(SVerbs* pVerbs, char* szVerb, int iCmd);
	BOOL IsValidCmd(SVerbs* pVerbs, UINT_PTR iCmd);
	DWORD GetMenuMsgId(SVerbs* pVerbs, int iCmd);
	SVerbs* GetVerbByCmd(SVerbs* pVerbs, UINT_PTR iCmd);
	pfCmdHandlerT DoVerbByCmd(SVerbs* pVerbs, int iCmd);
	pfCmdHandlerT DoVerbByVerb(SVerbs* pVerbs, const char* szVerb);

	static DWORD WINAPI CommandThread(LPVOID lParam);
	void IterateSelection();

	DWORD DoEncryptCompress(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoEncryptCompressCopy(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoSfxEncDef(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoSfxEncName(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoDecrypt(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoWipe(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoOpen(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoDebug(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoClearKeys(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoRename(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoNothing(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoEncryptOnly(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoBruteForce(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoHexCopy(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoKeyFile(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoNotifyMe(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoDocs(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoAbout(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoBugReport(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoLicenseMgr(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoEnglish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoDanish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoGerman(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoDutch(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoHungarian(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoSpanish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoFrench(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoItalian(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoNorwegian(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoSwedish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoBrazilPortuguese(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoPolish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoRussian(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoCzech(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);
	DWORD DoFinnish(itEventT eventId, HWND hProgressWnd, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile, CParam** ppParam);

	DWORD DoKeyFileHelper(HWND hProgressWnd, const TCHAR* szFolder);
public:
	DWORD CallAxCrypt(HWND hProgressWnd, LPTSTR szParams);
private:
	DWORD DoAxCrypt(HWND hProgressWnd, LPTSTR szOption, IShellFolder* pShellFolder, LPCITEMIDLIST pidlFile);
public:
	void SetBatch(int iBatch = -1);
private:
	LPTSTR GetBatchStr();
};

typedef CShellExt* LPCSHELLEXT;