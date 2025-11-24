#ifndef	_AXCOMMON
#define	_AXCOMMON
/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
	AxCommon.h						Common stuff for server and extension

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2002-08-02              Rel 1.2

*/
#include "Utility.h"
#include "CConfig.h"

#if !defined(_DEBUGHEAP) && defined(_DEBUG)
#include "CHeapCheck.h"
#endif

//
//	Constants for the server and the shell extension
//
//extern const TCHAR *szAxCryptCLSID;
extern CPtrTo<TCHAR> gszAxCryptMessageDLL;
extern CPtrTo<TCHAR> gszAxCryptMutex;
extern CPtrTo<TCHAR> gszAxCryptFileMap;
extern CPtrTo<TCHAR> gszAxCryptEventSend;
extern CPtrTo<TCHAR> gszAxCryptEventReceive;
extern CPtrTo<TCHAR> gszAxCryptProgID;
extern CPtrTo<TCHAR> gszAxCryptProgDesc;
extern CPtrTo<TCHAR> gszAxCryptFileExt;
extern CPtrTo<TCHAR> gszAxCryptCLSID;
extern CPtrTo<TCHAR> gszAxCryptExternalName;
extern CPtrTo<TCHAR> gszAxCryptInternalName;
extern CPtrTo<TCHAR> gszXecretsFileShellExtName;
extern CPtrTo<TCHAR> gszAxCryptIconName;
extern CPtrTo<TCHAR> gszXecretsUrl;
extern CPtrTo<TCHAR> gszAxCryptSfxName;
extern CPtrTo<TCHAR> gszAxCryptProgramName;
extern CPtrTo<TCHAR> gszAxCryptCompanyName;
extern CPtrTo<TCHAR> gszAxCryptCopyright;
extern bool gfAxCryptShowNoVersion;

//
//	Some string constants.
//
extern CPtrTo<TCHAR> gszAxCryptRegKey;
extern const TCHAR* szAxCryptDefFileExt;
extern const TCHAR* szAxBruteDLL;

extern const TCHAR* szRegValKeyWrapIterations;
extern const TCHAR* szRegValDefaultLanguageId;
extern const TCHAR* szRegValSaveEncKey;
extern const TCHAR* szRegValSaveDecKey;
extern const TCHAR* szRegValNoUnsafeWipeWarn;
extern const TCHAR* szRegValNoDecryptMode;
extern const TCHAR* szRegValServerMode;
extern const TCHAR* szRegValServerErrorShell;
extern const TCHAR* szRegValCompressLevel;
extern const TCHAR* szRegValNoRenameMenu;
extern const TCHAR* szRegValBruteForceCheck;
extern const TCHAR* szRegValTryBrokenFile;
extern const TCHAR* szRegValAfterNotifyName;
extern const TCHAR* szRegValAllowAnyExtension;
extern const TCHAR* szRegValFastModeDefault;
extern const TCHAR* szRegValKeyFileInfo;
extern const TCHAR* szRegValKeyFileNotRemovable;
extern const TCHAR* szRegValKeyFileUseInfo;
extern const TCHAR* szRegValKeyFileNotEncrypt;
extern const TCHAR* szRegValSystemFolderWarn;
extern const TCHAR* szRegValBugReport;
extern const TCHAR* szRegValDocumentationName;
extern const TCHAR* szRegValKeepTimeStamp;
extern const TCHAR* szRegValLicensee;
extern const TCHAR* szRegValSignature;
extern const TCHAR* szRegValShowActivationMenu;
extern const TCHAR* szRegValWipePasses;

extern const TCHAR* szRegValProductName;
extern const TCHAR* szRegValCLSID;
extern const TCHAR* szRegValFileExt;

extern const TCHAR* szRegValUseEntropyPool;
extern const TCHAR* szRegValueEntropyPool;
extern const TCHAR* szRegValEventLogLevel;
extern const TCHAR* szRegValNotifyEmail;
extern const TCHAR* szRegValNotifyPreference;
extern const TCHAR* szRegValStartMenuFolder;
extern const TCHAR* szRegValExeFolder;
extern const TCHAR* szRegValInstallDir;
extern const TCHAR* szRegValInstallerLanguage;
extern const TCHAR* szRegValVersion;
extern const TCHAR* szRegValDefault;
extern const TCHAR* szRegValAllowPrograms;
extern const TCHAR* szRegValDisableSaveEncryptionKey;
extern const TCHAR* szRegValDisableSaveDecryptionKey;

extern const TCHAR* szSigsXML;              ///< Hardcoded name of signature XML in same folde as exe
extern const unsigned char bPublicRootKey[];
extern const size_t cbPublicRootKey;

//
//  This should _not_ be read from the registry at need!
//  To change, we require a restart.
//
extern BOOL gfNoDecryptMode;
//
//  Common utility functions
//
extern const _TCHAR* InitGlobalStrings(HINSTANCE hInstance);
extern void UnInitGlobalStrings(void);

extern DWORD MessageWaitForSingleObject(HANDLE hObject, DWORD dwTimeout = INFINITE);
extern DWORD DlgMessageWaitForSingleObject(HWND hDlg, HANDLE hObject, DWORD dwTimeout = INFINITE);
extern bool IsParentTopMost(HWND hWnd);
//
//  Progress Dialog
//
#define IDS_OPERATION 1001
#define IDS_FILE 1002
//
//  The GWL_USERDATA of the actual progress-bar window, wich is returned
//  by Create(), is used to communicate the called process id when needed
//  to uniquely identify the window.
//
//  The GWL_USERDATA of the dialog it self is used as follows:
//      2   => The window is not visible and the timer has not been started.
//      1   => The timer has been started once. The visible state is unknown.
//      0   => The cancel button has been pressed. The visible state is unknown.
//
class CProgressDialog {
	HWND m_hDlg;
	HWND m_hProgress;
	static INT_PTR CALLBACK dlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

public:
	CProgressDialog();
	~CProgressDialog();
	void Destroy();
	HWND Create(HINSTANCE hInstance, DWORD dwIDD, HWND hParent, const _TCHAR* szTitleBar);
	HWND Wnd();
};

extern HINSTANCE ghInstance;

//
//	Do not include heap check-points in the distribution release,
//	or when using the VC++ heap (_DEBUGHEAP).
//
#if !defined(_DEBUGHEAP) && defined(_DEBUG)
#define	HEAP_CHECK_BEGIN(Where, AllowedLeak) {CHeapCheck utHeapCheck(Where, AllowedLeak);{
#define HEAP_CHECK_END }}
#else
#define	HEAP_CHECK_BEGIN(Where, AllowedLeak)
#define	HEAP_CHECK_END
#endif

#endif	_AXCOMMON