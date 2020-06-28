/*! \file
\brief Registration Dialog

@(#) $Id$

Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
Server or Web Storage of Document Files.

Copyright (C) 2009 Svante Seleborg/Axon Data, All rights reserved.

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
*/
#include "StdAfx.h"
#include <winhttp.h>
#include <string>
#include <iostream>
#include <sstream>
#include "../XecretsFileCommon/CVersion.h"
#include "../XecretsFileCommon/CRegistry.h"
#include "../AxWinLib/IWinVersion.h"
#include "Dialog.h"

using namespace std;

//
//	Arguments to dialog box.
//
struct SRegistrationDlgInfo {
	axpl::ttstring sEmail;					// The e-mail provided
};

//
//	Dialog procedure for the registration dialog
//
INT_PTR CALLBACK DlgProcRegistration(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
) {
	SRegistrationDlgInfo* pRegistrationDlgInfo;
	switch (uMsg) {
	case WM_INITDIALOG:
		pRegistrationDlgInfo = (SRegistrationDlgInfo*)lParam;
		// This is to handle a compiler problem with warnings when using the 64-bit compatible defines
#pragma warning ( push )
#pragma warning ( disable : 4244 )
		(void)SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
#pragma warning ( pop )

		SetDlgItemText(hwndDlg, IDC_REGISTRATIONPROMPT, L"Let us know your e-mail so we can notify you of updates!\n\nYou can always change this later, or leave blank for now.\n\nWe'll also send limited non-personal information about version and language to us.");
		SetDlgItemText(hwndDlg, IDC_ENTERREGISTRATION, L"Your e-mail");
		SetDlgItemText(hwndDlg, IDOK, CMessage().AppMsg(INF_IDOK).GetMsg());
		SetDlgItemText(hwndDlg, IDCANCEL, CMessage().AppMsg(INF_IDCANCEL).GetMsg());
		SetDlgItemText(hwndDlg, IDC_REGISTRATIONEMAIL, pRegistrationDlgInfo->sEmail.c_str());

		{
			axpl::ttstring s = MainDlgTitleBar();
			SetWindowText(hwndDlg, s.c_str());
		}

		// Ensure that we are not obscured by parent, if possible.
		SetWindowPos(hwndDlg, IsParentTopMost(hwndDlg) ? HWND_TOPMOST : GetParent(hwndDlg), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetForegroundWindow(hwndDlg);

		// We always center the license dialog in the center of the screen, one reason
		// being that it may have the START-bar as it's parent, and centering around that
		// is not a very good thing.
		CenterWindow(hwndDlg, true);
		SetFocus(GetDlgItem(hwndDlg, IDC_LICENSEE));
		return FALSE;

	case WM_COMMAND:
	{
		pRegistrationDlgInfo = (SRegistrationDlgInfo*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
		_TCHAR szEmail[250];
		switch (LOWORD(wParam)) {
		case IDOK:
			::GetDlgItemText(hwndDlg, IDC_REGISTRATIONEMAIL, szEmail, sizeof szEmail);
			pRegistrationDlgInfo->sEmail = szEmail;
			EndDialog(hwndDlg, TRUE);
			break;
		case IDCANCEL:
			EndDialog(hwndDlg, FALSE);
			break;
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
}

/// \brief Get a Windows version string formatted for Xecrets File registration
wstring
GetWindowsVersionString() {
	auto_ptr<AxLib::IWinVersion> pIWinVersion(AxLib::IWinVersion::New());

	/*
	"Win95"
	"Win98"
	"WinME"
	"Win2K"
	"WinXP"
	"W2003"
	"WINHS"
	"WinVista"
	"WinVistax64"
	"Win2008"
	"WinXPx64"
	"W2003x64"
	"Win2008x64"
	"Win7"
	"Win7x64"
	"WinXX"
	*/

	int version = pIWinVersion->GetVersion();
	switch (version & ~AxLib::X64) {
	case AxLib::WINXX:
		return L"WinXX";
	case AxLib::WIN95:
		return L"Win95";
	case AxLib::WIN98:
		return L"Win98";
	case AxLib::WINME:
		return L"WinME";
	case AxLib::NT3:
		return L"WinXX";
	case AxLib::NT4:
		return L"WinxXX";
	case AxLib::WIN2K:
		return L"Win2K";
	case AxLib::WINXP:
		return ((version & AxLib::X64) == AxLib::X64) ? L"WinXPx64" : L"WinXP";
	case AxLib::W2003:
		return ((version & AxLib::X64) == AxLib::X64) ? L"W2003x64" : L"W2003";
	case AxLib::WINVISTA:
		return ((version & AxLib::X64) == AxLib::X64) ? L"WinVistax64" : L"WinVista";
	case AxLib::WIN2008:
		return ((version & AxLib::X64) == AxLib::X64) ? L"Win2008x64" : L"Win2008";
	case AxLib::WIN7:
		return ((version & AxLib::X64) == AxLib::X64) ? L"Win7x64" : L"Win7";
	case AxLib::WINHS:
		return L"WINHS";
	default:
		break;
	}

	return L"WinxXX";
}

wstring
GetTempIniPath()
{
	DWORD cb = GetTempPath(0, NULL);
	vector<wchar_t> szTempPath(cb);
	cb = GetTempPath(cb, &szTempPath[0]);
	return wstring(&szTempPath[0], cb) + AXPRODUCTFILENAME L".ini";
}

wstring GetTempIniValue(wstring sKeyName) {
	wstring sTempIniPath = GetTempIniPath();
	vector<wchar_t> szValue(100);
	DWORD cb = GetPrivateProfileString(L"Previous", sKeyName.c_str(), L"", &szValue[0], szValue.capacity(), sTempIniPath.c_str());
	return wstring(&szValue[0], cb);
}

wstring
GetDefaultEmail()
{
	return GetTempIniValue(L"Email");
}

wstring
GetPreviousVersion()
{
	return GetTempIniValue(L"Version");
}

wstring
GetDefaultLanguageId() {
	DWORD dwLanguageId = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValDefaultLanguageId).GetDword(0);
	if (dwLanguageId == 0) {
		return L"";
	}
	wostringstream stm;
	stm << dwLanguageId;
	return stm.str();
}

/// \brief Attempt to send registration info via the web to Axantum
/// \param email The email, if any, to send along.
void
Register(axpl::ttstring& email, std::wstring& sVersion) {
	const wchar_t* szUserAgent = AXPRODUCTFILENAME L" Registration Client/1.0";
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG pc;
	ZeroMemory(&pc, sizeof pc);
	BOOL bHasProxyConfig = WinHttpGetIEProxyConfigForCurrentUser(&pc) && pc.lpszProxy != NULL;

	// Use WinHttpOpen to obtain a session handle.
	if (bHasProxyConfig) {
		hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, pc.lpszProxy, pc.lpszProxyBypass, 0);
	}
	else {
		hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	}

	if (pc.lpszAutoConfigUrl != NULL) {
		GlobalFree(pc.lpszAutoConfigUrl);
	}
	if (pc.lpszProxy != NULL) {
		GlobalFree(pc.lpszProxy);
	}
	if (pc.lpszProxyBypass != NULL) {
		GlobalFree(pc.lpszProxyBypass);
	}
	ZeroMemory(&pc, sizeof pc);

	// Specify an HTTP server.
	// Update=1, Critical=1, Decline=1
	// Program=AXPRODUCTFILENAME
	// Previous=[old-version]
	// Version=[this-version]
	// Windows=Win95 | Win98 | WinME | NTn.n | Win2K, WinXP, W2003, WinVista, WinXX (unknown)
	//         new, needs update in service: Win2008, WinXPx64, W2003x64, Win2008x64, Win7, Win7x64
	// Language=
	if (hSession) {
		hConnect = WinHttpConnect(hSession, L"account.axcrypt.net", INTERNET_DEFAULT_HTTPS_PORT, 0);
	}

	wstring urlPathPart = L"/RegisterLegacyAxCrypt?Program=" AXPRODUCTFILENAME;
	urlPathPart += L"&Windows=" + GetWindowsVersionString();
	urlPathPart += L"&email=" + email;
	if (!sVersion.empty()) {
		urlPathPart += L"&Version=" + sVersion;
	}
	urlPathPart += L"&Update=1";
	wstring sPreviousVersion = GetPreviousVersion();
	if (!sPreviousVersion.empty()) {
		urlPathPart += L"&Previous=" + sPreviousVersion;
	}
	wstring sLanguageId = GetDefaultLanguageId();
	if (!sLanguageId.empty()) {
		urlPathPart += L"&Language=" + sLanguageId;
	}

	// Create an HTTP request handle.
	if (hConnect) {
		hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPathPart.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE);
	}

	// Send a request.
	if (hRequest) {
		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	}

	// End the request.
	if (bResults) {
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}

	// Keep checking for data until there is nothing left.
	if (bResults) {
		DWORD dwSize = 0;
		do {
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				break;
			}

			// Allocate space for the buffer.
			auto_ptr<char> pszOutBuffer(new char[dwSize + 1]);
			if (!pszOutBuffer.get()) {
				break;
			}
			else {
				// Read the data.
				ZeroMemory(pszOutBuffer.get(), dwSize + 1);
				DWORD dwDownloaded = 0;
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer.get(), dwSize, &dwDownloaded)) {
					break;
				}
			}
		} while (dwSize > 0);

		// Update the registration info
		wstring sTempIniPath = GetTempIniPath();
		WritePrivateProfileString(L"Previous", L"Email", email.c_str(), sTempIniPath.c_str());
		WritePrivateProfileString(L"Previous", L"Version", CVersion(ghInstance).GenericVersionString().c_str(), sTempIniPath.c_str());
	}

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
}

/// \brief Prompt for registration info etc
/// \param hWnd Handle to parent window
void
AskForRegistration(HWND hWnd, std::wstring& sVersion) {
	// Stay silent if this is done in server mode.
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		SRegistrationDlgInfo dlgInfo;
		dlgInfo.sEmail = GetDefaultEmail();

		while (true) {
#ifdef _DEBUG
			HWND hParent = hWnd;
#else
			// This screws up the debugger
			HWND hParent = hWnd ? hWnd : GetForegroundWindow();
#endif
			switch (DialogBoxParam(
				ghInstance,
				MAKEINTRESOURCE(IDD_REGISTRATION),
				hParent,
				DlgProcRegistration,
				(LPARAM)&dlgInfo)) {
			case TRUE:
				// User pressed OK
				Register(dlgInfo.sEmail, sVersion);
				return;
			case FALSE:
				// User pressed Cancel
				if (MessageBox(hParent, L"Are you sure? It helps us improve the program!", axpl::ttstring(MainDlgTitleBar()).c_str(), MB_YESNO) == IDYES) {
					return;
				}
				break;
			default:
				CMessage().AppMsg(MSG_INTERNAL_ERROR, _T("AskForRegistration()")).ShowError();
				return;
			}
		}
	}
}