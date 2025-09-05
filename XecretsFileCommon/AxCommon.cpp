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
	AxCommon.cpp					Some constant definitions shared between server and extension

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2002-07-25              Added common code
									2002-08-02              Rel 1.2

*/
#include "stdafx.h"

#include "commctrl.h"
#include <ShlWapi.h>

#include <memory>
using namespace std;

#include "AxCommon.h"
#include "CVersion.h"
#include "CConfig.h"
#include "CRegistry.h"
#include "../AxWinLib/GetModuleFileName.h"
#include "../XecretsFileCommon/CFileName.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Common.cpp"

CPtrTo<TCHAR> gszRegKeyEventLog;

CPtrTo<TCHAR> gszAxCryptRegKey;
CPtrTo<TCHAR> gszAxCryptMessageDLL;
CPtrTo<TCHAR> gszAxCryptMutex;
CPtrTo<TCHAR> gszAxCryptFileMap;
CPtrTo<TCHAR> gszAxCryptEventSend;
CPtrTo<TCHAR> gszAxCryptEventReceive;
CPtrTo<TCHAR> gszAxCryptProgID;
CPtrTo<TCHAR> gszAxCryptProgDesc;
CPtrTo<TCHAR> gszAxCryptFileExt;
CPtrTo<TCHAR> gszAxCryptCLSID;
CPtrTo<TCHAR> gszAxCryptExternalName;
CPtrTo<TCHAR> gszAxCryptInternalName;
CPtrTo<TCHAR> gszXecretsFileShellExtName;
CPtrTo<TCHAR> gszAxCryptIconName;
CPtrTo<TCHAR> gszXecretsUrl;
CPtrTo<TCHAR> gszAxCryptSfxName;
CPtrTo<TCHAR> gszAxCryptProgramName;
CPtrTo<TCHAR> gszAxCryptCompanyName;
CPtrTo<TCHAR> gszAxCryptCopyright;
bool gfAxCryptShowNoVersion = false;

const TCHAR* szAxCryptDefFileExt = AXENCRYPTEDFILEEXT;
const TCHAR* szAxBruteDLL = _T("AxBrute.dll");

// The following lists ALL registry keys - all that are used, regardless if they are only for the installer etc.
// You MUST also update FileCmd.cpp CmdRemoveFromRegistry() if you add a key. The list of values to remove should of
// course be defined here, but for now, just remember.

// HKEY_CURRENT_USER / gszAxCryptRegKey
const TCHAR* szRegValSaveEncKey = _T("SaveEncKey");
const TCHAR* szRegValSaveDecKey = _T("SaveDecKey");
const TCHAR* szRegValNoUnsafeWipeWarn = _T("NoShowUnsafeWipeWarn");
const TCHAR* szRegValNoDecryptMode = _T("NoDecryptMode");
const TCHAR* szRegValServerMode = _T("ServerMode");
const TCHAR* szRegValServerErrorShell = _T("ServerErrorShellCmd");
const TCHAR* szRegValCompressLevel = _T("CompressThreshold");
const TCHAR* szRegValNoRenameMenu = _T("DisableRenameMenu");
const TCHAR* szRegValBruteForceCheck = _T("BruteForceCheck");
const TCHAR* szRegValTryBrokenFile = _T("TryBrokenFile");
const TCHAR* szRegValAllowAnyExtension = _T("AllowAnyExtension");
const TCHAR* szRegValFastModeDefault = _T("FastModeDefault"); // DWORD
const TCHAR* szRegValKeyFileInfo = _T("NoShowKeyFileInfo"); // DWORD
const TCHAR* szRegValKeyFileNotRemovable = _T("NoShowKeyFileNotRemovable"); // DWORD
const TCHAR* szRegValKeyFileUseInfo = _T("NoShowKeyFileUseInfo"); // DWORD
const TCHAR* szRegValKeyFileNotEncrypt = _T("NoShowKeyFileNotEncrypt"); // DWORD
const TCHAR* szRegValKeepTimeStamp = _T("KeepTimeStamp"); // DWORD
const TCHAR* szRegValLicensee = _T("Licensee"); // REG_SZ
const TCHAR* szRegValSignature = _T("Signature"); // REG_SZ
const TCHAR* szRegValShowActivationMenu = _T("ShowActivationMenu"); // REG_SZ
const TCHAR* szRegValSystemFolderWarn = _T("SystemFolderWarn"); // DWORD
const TCHAR* szRegValWipePasses = _T("WipePasses"); // DWORD

// HKEY_LOCAL_MACHINE / gszAxCryptRegKey
const TCHAR* szRegValProductName = _T("ProductName");
const TCHAR* szRegValCLSID = _T("CLSID");
const TCHAR* szRegValFileExt = _T("FileExtension");

// HKEY_LOCAL_MACHINE / gszAxCryptRegKey
// and
// HKEY_CURRENT_USER / gszAxCryptRegKey
const TCHAR* szRegValDefaultLanguageId = _T("DefaultLanguageId");
const TCHAR* szRegValKeyWrapIterations = _T("KeyWrapIterations");

// HKEY_LOCAL_MACHINE / gszAxCryptRegKey
// and/or
// HKEY_CURRENT_USER / gszAxCryptRegKey
// These are values introduced by the installer, but we keep track of them here and specifically
// we delete them via the uninstall logic
const TCHAR* szRegValAfterNotifyName = _T("AfterNotifyName");
const TCHAR* szRegValBugReport = _T("BugReport");
const TCHAR* szRegValDocumentationName = _T("DocumentationName");
const TCHAR* szRegValUseEntropyPool = _T("UseEntropyPool");
const TCHAR* szRegValueEntropyPool = _T("EntropyPool");
const TCHAR* szRegValEventLogLevel = _T("EventLogLevel");
const TCHAR* szRegValNotifyEmail = _T("NotifyEmail");
const TCHAR* szRegValNotifyPreference = _T("NotifyPreference");
const TCHAR* szRegValStartMenuFolder = _T("Start Menu Folder");
const TCHAR* szRegValExeFolder = _T("ExeFolder");
const TCHAR* szRegValInstallDir = _T("Install_Dir");
const TCHAR* szRegValInstallerLanguage = _T("InstallerLanguage");
const TCHAR* szRegValVersion = _T("Version");
const TCHAR* szRegValDefault = _T("");
const TCHAR* szRegValAllowPrograms = _T("AllowPrograms"); // DWORD

// HKEY_LOCAL_MACHINE / gszAxCryptRegKey
const TCHAR* szRegValDisableSaveEncryptionKey = _T("DisableSaveEncryptionKey"); // DWORD
const TCHAR* szRegValDisableSaveDecryptionKey = _T("DisableSaveDecryptionKey"); // DWORD

BOOL gfNoDecryptMode = FALSE;

// This is the Axon Data code signing public key and accompanying info
const TCHAR* szSigsXML = _T("Sigs.xml");    ///< Hardcoded name of signature XML in same folde as exe
const unsigned char bPublicRootKey[] = {
0x30, 0x82, 0x01, 0xb5, 0x30, 0x82, 0x01, 0x4d, 0x06, 0x07, 0x2a, 0x86,
0x48, 0xce, 0x3d, 0x02, 0x01, 0x30, 0x82, 0x01, 0x40, 0x02, 0x01, 0x01,
0x30, 0x3c, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, 0x02,
0x31, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
0xff, 0xff, 0x30, 0x64, 0x04, 0x30, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0xff, 0xff, 0xff, 0xfc, 0x04, 0x30, 0xb3, 0x31, 0x2f, 0xa7,
0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f,
0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d,
0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef, 0x04, 0x61, 0x04, 0xaa,
0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59,
0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf,
0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7, 0x36,
0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9,
0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d,
0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f, 0x02,
0x31, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a,
0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5,
0x29, 0x73, 0x02, 0x01, 0x01, 0x03, 0x62, 0x00, 0x04, 0x40, 0x94, 0x81,
0x80, 0x5b, 0xc9, 0xca, 0xd4, 0x28, 0x40, 0xd5, 0xed, 0xa0, 0x5f, 0x1c,
0x4d, 0x9a, 0x74, 0x0c, 0x05, 0xa9, 0x79, 0xee, 0x8b, 0x27, 0x72, 0xea,
0x49, 0xef, 0xb3, 0x5a, 0x37, 0x2f, 0x28, 0x5c, 0x09, 0xb3, 0x30, 0x26,
0xe2, 0x3f, 0x2f, 0x2a, 0x59, 0x2b, 0x52, 0x8f, 0xca, 0x80, 0xe2, 0x3b,
0x07, 0xa8, 0x1c, 0xf3, 0x17, 0x12, 0xb8, 0xfd, 0xf6, 0xb0, 0xbc, 0xb6,
0xb4, 0xac, 0xbd, 0x82, 0xb4, 0xe1, 0xee, 0x13, 0x9c, 0x4d, 0xc6, 0x12,
0x72, 0x37, 0xc2, 0xe0, 0xbd, 0x1c, 0x81, 0x08, 0x1b, 0xac, 0xc7, 0xef,
0xf9, 0x5c, 0x3d, 0x34, 0xcc, 0xa8, 0xe4, 0x11, 0xc5 };
const size_t cbPublicRootKey = sizeof bPublicRootKey;

static const _TCHAR* MsgProxy(const _TCHAR* sz) {
	static _TCHAR szMsg[200];

	_tcsncpy_s(szMsg, sizeof szMsg / sizeof szMsg[0], sz, sizeof szMsg / sizeof szMsg[0]);
	szMsg[sizeof szMsg / sizeof szMsg[0] - 1] = _T('\0');
	return szMsg;
}
/// \brief Properly initialize and format all global strings, customizing with product name when appropriate.
///
/// Since this code is used in the shell extension as well, we can't just exit via assert here, since that'll kill
/// the shell too...
/// \param hInstance Our instance handle
/// \return An error message if a fatal error occurs, or NULL if all is ok.
const _TCHAR*
InitGlobalStrings(HINSTANCE hInstance) {
	// Start to initialize with info from the configuration XML which we either assume has been verified
	// or assume will be verified, or we simply don't really care at this point.

	// Find the path to the executable folder of ourselves.
	auto_ptr<_TCHAR> szModulePath(MyGetModuleFileName(hInstance));
	if (szModulePath.get() == NULL) {
		return _T("MyGetModuleFileName(hInstance) failed");
	}
	_TCHAR* szModuleName = PathFindFileName(szModulePath.get());
	if (!PathRemoveFileSpec(szModulePath.get())) {
		return _T("PathRemoveFileSpec(szModulePath.get()) failed");
	}

	auto_ptr<CConfig> pConfig(new CConfig(szSigsXML, szModulePath.get()));
	if (pConfig.get() == NULL) {
		return _T("Memory allocation for pConfig failed");
	}

	// Validate that we actually have some signature XML
	if (pConfig->GetSigsXML() == NULL) {
		return MsgProxy(pConfig->GetLastErrorMsg().c_str());
	}

	// Load the configuration file as named in the signature XML, but still from the current directory
	if (!pConfig->LoadConfig(pConfig->GetSigsXML(), szModulePath.get())) {
		return MsgProxy(pConfig->GetLastErrorMsg().c_str());
	}

	gszAxCryptMessageDLL = CopySz(pConfig->GetElementConfig(_T("MessagesName")).c_str());
	if (!gszAxCryptMessageDLL || !*gszAxCryptMessageDLL) {
		return _T("Could not find config element MessagesName");
	}

	if (ghMsgModule == NULL) {
		if (!(ghMsgModule = LoadLibraryEx(
			CFileName().SetPath2ExeName(hInstance).SetTitle((LPTSTR)gszAxCryptMessageDLL).Get(),
			NULL,
			LOAD_LIBRARY_AS_DATAFILE)).IsValid()) {
			FatalAppExit(0, _T("Failed to load application texts. Immediate exit."));
		}
	}

	// We now have the configuration XML loaded and can pick-up static global parameter strings
	gszAxCryptExternalName = CopySz(pConfig->GetElementConfig(_T("ExternalName")).c_str());
	if (!gszAxCryptExternalName || !*gszAxCryptExternalName) {
		return _T("Could not find config element ExternalName");
	}

	gszAxCryptInternalName = CopySz(pConfig->GetElementConfig(_T("InternalName")).c_str());
	if (!gszAxCryptInternalName || !*gszAxCryptInternalName) {
		return _T("Could not find config element InternalName");
	}

	gszAxCryptCompanyName = CopySz(pConfig->GetElementConfig(_T("CompanyName")).c_str());
	if (!gszAxCryptCompanyName || !*gszAxCryptCompanyName) {
		return _T("Could not find config element CompanyName");
	}

	gszAxCryptRegKey = CopySz(pConfig->GetElementConfig(_T("RegistryPath")).c_str());
	if (!gszAxCryptRegKey || !*gszAxCryptRegKey) {
		return _T("Could not find config element RegistryPath");
	}

	gszXecretsFileShellExtName = CopySz(pConfig->GetElementConfig(_T("ShellExtName")).c_str());
	if (!gszXecretsFileShellExtName || !*gszXecretsFileShellExtName) {
		return _T("Could not find config element ShellExtName");
	}

	gszAxCryptIconName = CopySz(pConfig->GetElementConfig(_T("ProgramIconName")).c_str());
	if (!gszAxCryptIconName || !*gszAxCryptIconName) {
		return _T("Could not find config element ProgramIconName");
	}

	gszXecretsUrl = CopySz(pConfig->GetElementConfig(_T("XecretsUrl")).c_str());
	if (!gszXecretsUrl || !*gszXecretsUrl) {
		return _T("Could not find config element XecretsUrl");
	}

	// Get the Selfdecryptor name, it's ok for it not to be defined - it might not be used.
	gszAxCryptSfxName = CopySz(pConfig->GetElementConfig(_T("SfxName")).c_str());

	gszAxCryptProgramName = CopySz(pConfig->GetElementConfig(_T("ProgramName")).c_str());
	if (!gszAxCryptProgramName || !*gszAxCryptProgramName) {
		return _T("Could not find config element ProgramName");
	}

	gszAxCryptCopyright = CopySz(pConfig->GetElementConfig(_T("Copyright")).c_str());
	if (!gszAxCryptCopyright || !*gszAxCryptCopyright) {
		return _T("Could not find config element Copyright");
	}

	// Get static options, these are configuration items that are never changed (since they are part of
	// the signed config).
	gfAxCryptShowNoVersion = axpl::TTStringCompareIgnoreCase(pConfig->GetElementAttributeConfig(_T("Options"), _T("ShowNoVersion")), _T("true"));

	gszAxCryptMutex = FormatSz(_T("%1Mutex"), gszAxCryptInternalName);
	gszAxCryptFileMap = FormatSz(_T("%1FileMapRequest"), gszAxCryptInternalName);
	gszAxCryptEventSend = FormatSz(_T("%1EventSend"), gszAxCryptInternalName);
	gszAxCryptEventReceive = FormatSz(_T("%1EventReceive"), gszAxCryptInternalName);
	gszAxCryptProgID = FormatSz(_T("%1.File"), gszAxCryptInternalName);
	gszAxCryptProgDesc = FormatSz(_T("%1 Privacy Wrapper File"), gszAxCryptExternalName);

	gszAxCryptCLSID = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValCLSID).GetSz();
	gszAxCryptFileExt = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValFileExt).GetSz(szAxCryptDefFileExt);

	// Ensure [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] exists - if it can exist. There's an issue with accounts
	// like NETWORK SERVICE - they don't sort of really have a concept of a current user, although they are mapped
	// to the S-1-5-20 SID, but there appears to be no sure way to get it to get permissions to write a subkey there...
	// One is recommended to use the RegOpenCurrentUser() in cooperation with ::RegDisablePredefinedCache() to be able to
	// use both HKCU and the opened one. The best would otherwise be always use the RegOpenCurrentUser of course.
	HKEY hkcu = NULL;
	if (RegOpenCurrentUser(KEY_WRITE | KEY_READ, &hkcu) != ERROR_SUCCESS) {
		::OutputDebugString(L"RegOpenCurrentUser HKCU failed.");
	}

	if (hkcu != NULL) {
		CRegistry().Root(hkcu).CreateKey(gszAxCryptRegKey);
		RegCloseKey(hkcu);
	}

	gfNoDecryptMode = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValNoDecryptMode).GetDword(FALSE);

	return NULL;
}
//
//  This must be called with an atexit() if the crypto heap is active to
//  ensure they are deleted before the heap itself goes...
//
void
UnInitGlobalStrings(void) {
	gszRegKeyEventLog = NULL;
	gszAxCryptRegKey = NULL;
	gszAxCryptMessageDLL = NULL;
	gszAxCryptMutex = NULL;
	gszAxCryptFileMap = NULL;
	gszAxCryptEventSend = NULL;
	gszAxCryptEventReceive = NULL;
	gszAxCryptProgID = NULL;
	gszAxCryptProgDesc = NULL;
	gszAxCryptCLSID = NULL;
	gszAxCryptFileExt = NULL;
}

//
//	Wait for event and process messages too.
//
DWORD
MessageWaitForSingleObject(HANDLE hObject, DWORD dwTimeout) {
	DWORD dwReturnCode;
	SetLastError(ERROR_SUCCESS);
	while (TRUE) {
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		// We're having problems with MsgWaitForMultipleObjects returning with WAIT_FAILED but with either unchanged or
		// no error code in GetLastError(). One thread on the Internet claims that using the Ex function solves the problem.
		if ((dwReturnCode = MsgWaitForMultipleObjectsEx(1,
			&hObject,
			dwTimeout,
			QS_ALLINPUT,
			0
		)) == (WAIT_OBJECT_0 + 1)) {
			continue; // Message in queue, no event...
		}
		else {
			// Additional fail-safe code for handling the WAIT_FAILED && ERROR_SUCCESS problem. Hopefully this won't cause hangs...
			if (dwReturnCode == WAIT_FAILED) {
				if (GetLastError() == ERROR_SUCCESS) {
					continue;
				}
			}
			if (dwReturnCode == WAIT_IO_COMPLETION) {
				continue;
			}
			return dwReturnCode;
		}
	}
}
//
//	Wait for event and process messages too, but also process a modeless dialog...
//
DWORD
DlgMessageWaitForSingleObject(HWND hDlg, HANDLE hObject, DWORD dwTimeout) {
	DWORD dwReturnCode;
	while (TRUE) {
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			if (!IsWindow(hDlg) || !IsDialogMessage(hDlg, &msg)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
		if ((dwReturnCode = MsgWaitForMultipleObjects(1,
			&hObject,
			FALSE,
			dwTimeout,
			QS_ALLINPUT)) == (WAIT_OBJECT_0 + 1)) {
			continue; // Message in queue, no event...
		}
		else {
			return dwReturnCode;
		}
	}
}

/// \brief Check if parent has WS_EX_TOPMOST style
/// \param hWnd The window to check. NULL is ok (returns false).
/// \return true if it has the WS_EX_TOPMOST style
bool
IsParentTopMost(HWND hWnd) {
	// Prepare to place the dialog in front when the time comes (the actual display is delayed)
	if (GetParent(hWnd) != NULL) {
		WINDOWINFO wi;
		ZeroMemory(&wi, sizeof wi);
		wi.cbSize = sizeof wi;
		CAssert(GetWindowInfo(GetParent(hWnd), &wi)).Sys(MSG_SYSTEM_CALL, _T("IsParentTopMost() [GetWindowInfo()]")).Throw();
		return (wi.dwExStyle & WS_EX_TOPMOST) != 0;
	}
	return false;
}

//
//  Create and initialize a progress dialogue, returning the
//  window handle.
//
CProgressDialog::CProgressDialog() {
	m_hProgress = m_hDlg = NULL;
}

CProgressDialog::~CProgressDialog() {
	Destroy();
}

void
CProgressDialog::Destroy() {
	if (m_hDlg != NULL) {
		// Must be SendMessage
		SendMessage(m_hDlg, WM_APP + 1, 0, 0);  // Destroy!
		m_hProgress = m_hDlg = NULL;
	}
}

INT_PTR CALLBACK
CProgressDialog::dlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG:
		SetWindowLongPtr(hDlg, GWLP_USERDATA, 2);
		SetFocus(GetDlgItem(hDlg, IDCANCEL));
		return FALSE;
	case WM_TIMER:
		if (wParam == 1 && GetWindowLongPtr(hDlg, GWLP_USERDATA) == 1) {
			KillTimer(hDlg, 1);
			SetWindowPos(hDlg, IsParentTopMost(hDlg) ? HWND_TOPMOST : GetParent(hDlg), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			ShowWindow(hDlg, SW_SHOWNORMAL);
			SetForegroundWindow(hDlg);
		}
		return TRUE;
		break;
	case WM_COMMAND:
		switch (wParam) {
		case IDCANCEL:
			SetWindowLongPtr(hDlg, GWLP_USERDATA, FALSE);
			return TRUE;
		default:
			break;
		}
	case WM_APP:
		SetWindowLongPtr(hDlg, GWLP_USERDATA, 2);
		KillTimer(hDlg, 1);
		ShowWindow(hDlg, SW_HIDE);
		return TRUE;
	case WM_APP + 1:
		DestroyWindow(hDlg);
		return TRUE;
	case WM_APP + 2:
		if (GetWindowLongPtr(hDlg, GWLP_USERDATA) == 2) {
			SetWindowLongPtr(hDlg, GWLP_USERDATA, 1);
			SetTimer(hDlg, 1, 1000, NULL);
		}
		return TRUE;

	case WM_DESTROY:
		KillTimer(hDlg, 1);
		return TRUE;
	default:
		break;
	}
	return FALSE;
}

HWND
CProgressDialog::Create(HINSTANCE hInstance, DWORD dwIDD, HWND hParent, const _TCHAR* szTitleBar) {
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		Destroy();

		if (hParent != NULL && !IsWindow(hParent)) {
			hParent = NULL;
		}

		m_hDlg = CreateDialog(hInstance, MAKEINTRESOURCE(dwIDD), hParent, dlgProc);
		CAssert(m_hDlg != NULL).Sys(MSG_SYSTEM_CALL, _T("CProgressDialog::Create [CreateDialog]")).Throw();

		SetWindowText(m_hDlg, szTitleBar);
		SetWindowLongPtr(m_hDlg, GWLP_USERDATA, 2);

		SetWindowLongPtr(GetDlgItem(m_hDlg, IDS_FILE), GWL_STYLE, GetWindowLongPtr(GetDlgItem(m_hDlg, IDS_FILE), GWL_STYLE) | SS_PATHELLIPSIS);
		SetDlgItemText(m_hDlg, IDCANCEL, CMessage().AppMsg(INF_IDCANCEL).GetMsg());

		//InitCommonControls();

		RECT rcClient;
		GetClientRect(m_hDlg, &rcClient);
		int cyVScroll = GetSystemMetrics(SM_CYVSCROLL);
		m_hProgress = CreateWindow(PROGRESS_CLASS,
			NULL,
			WS_CHILD | WS_VISIBLE,
			rcClient.left,
			rcClient.bottom - cyVScroll,
			rcClient.right, cyVScroll,
			m_hDlg,
			NULL,
			hInstance,
			NULL);
		CAssert(m_hProgress != NULL).Sys(MSG_SYSTEM_CALL, _T("CProgressDialog::Create [CreateWindow]")).Throw();
		PostMessage(m_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
	}
	return m_hProgress;
}

HWND
CProgressDialog::Wnd() {
	return m_hProgress;
}