/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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
	Dialog.cpp						Secure dialog procedures, handling password entry etc.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2002-08-05              Rel 1.2

*/
//
//	Handle all user interaction
//
//	As far as is possible, we try to ensure that such things as passwords are
//	never stored in memory that is not locked in memory, to ensure that they
//	are not written to disk as virtual memory.
//
#include	"StdAfx.h"
#include    <shlwapi.h>
#include    <shellapi.h>
#include    <commdlg.h>
#include	"../XecretsFileCommon/CVersion.h"
#include    "../XecretsFileCommon/CRegistry.h"
#include    "Dialog.h"
#include    "../AxWinLib/IStaticHyperlink.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "Dialog.cpp"
/// \brief Small helper to provide a unified title-bar for dialogs, including these.
/// This takes care of issues like writing out trial info if any etc. Lots of hybrid
/// code-styling here...
axpl::ttstring MainDlgTitleBar(HINSTANCE hInstance) {
	axpl::ttstring s = CVersion(hInstance).String(gfAxCryptShowNoVersion);     // This is the basic title-bar string
	// If we have restrictions on uses
	if (gpTrialMgr && gpRestrictMgr) {
		if (gpRestrictMgr->Has(_TT("uses"))) {
			int iMax = gpRestrictMgr->GetInt(_TT("uses"));
			int iCtr = gpTrialMgr->Get();
			s = s + (TCHAR*)(CMessage().AppMsg(INF_TRIALCOUNT, iCtr, iMax).GetMsg());
		}
	}
	return s;
}

//
struct SSafeEdit {
	LPSTR szPassphrase;
	unsigned uiLen;
	WNDPROC lpfnOldWndProc;
	BOOL fIsWindowUnicode;				// TRUE if chars received are in Unicode.
	BOOL fIsPasting;                    // true during paste operation.
};
//
//	Arguments to dialog box.
//
struct SDlgInfo {
	char* szPassphrase;                     // Passphrase always Ansi, for better or worse
	const TCHAR* szFileName;
	auto_ptr<_TCHAR> szKeyFileName;
	int IDDMainPrompt;
	BOOL fSaveInCache_E;      // Set check-box if the user wants to save the Enc-key
	BOOL fSaveInCache_D;      // Set check-box if the user wants to save the Dec-key
	bool fDisableSaveInCache_E;
	bool fDisableSaveInCache_D;
};

/// \brief Get a file name with an open dialog in an allocated string.
_TCHAR*
AGetOpenFileNameDialog(HWND hWnd, _TCHAR* szDefault, bool fAlwaysIncludeDefaultFilter) {
	// Build the filter string, i.e. for example "*.txt\0*.txt\0\0"
	// They don't make it easy by using nul chars...
	_TCHAR* szPathExt = PathFindExtension(szDefault);
	_TCHAR szFilter[1024 + 1024];    // wsprintf guarantee (but we call it twice, so...)
	_TCHAR* szNextFilter = szFilter;
	if (szPathExt[0]) {
		wsprintf(szNextFilter, _T("*%s"), szPathExt);
		szNextFilter = &szNextFilter[lstrlen(szNextFilter) + 1];
		wsprintf(szNextFilter, _T("*%s"), szPathExt);
		szNextFilter = &szNextFilter[lstrlen(szNextFilter) + 1];
	}
	if (!szPathExt[0] || fAlwaysIncludeDefaultFilter) {
		// Copy default filter, if no extension.
		CopyMemory(szNextFilter, _T("*.*\0*.*\0"), sizeof _T("*.*\0*.*\0"));
		szNextFilter += sizeof _T("*.*\0*.*\0") / sizeof _TCHAR;
	}
	szNextFilter[0] = _T('\0');
	szNextFilter = NULL;

	auto_ptr<_TCHAR> szFileName(new _TCHAR[_MAX_PATH]);
	_tcsncpy_s(szFileName.get(), _MAX_PATH, szDefault, _MAX_PATH);

	OPENFILENAME ofn;
	ZeroMemory(&ofn, sizeof ofn);
	ofn.lStructSize = sizeof ofn;
	ofn.hwndOwner = hWnd;
	ofn.lpstrFilter = szFilter;
	ofn.nFilterIndex = 1;
	ofn.lpstrDefExt = szPathExt[0] ? szPathExt + 1 : NULL;
	ofn.lpstrFile = szFileName.get();
	ofn.nMaxFile = _MAX_PATH;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
	if (!GetOpenFileName(&ofn)) {
		return NULL;
	}
	return szFileName.release();
}
//
//  Parameter package for the warning dialogue.
//
class CWarnDlg {
public:
	LPTSTR szMsg;
	LPTSTR szNotAgainMsg;
	BOOL fNotAgain;

	CWarnDlg() { szMsg = szNotAgainMsg = NULL; }
	~CWarnDlg() {
		if (szMsg != NULL) delete szMsg;
		if (szNotAgainMsg != NULL) delete szNotAgainMsg;
	}
};

BOOL
WindowRectToClientRect(HWND hwndDlg, RECT* prect) {
	POINT point;
	point.x = prect->left;
	point.y = prect->top;
	if (!ScreenToClient(hwndDlg, &point)) {
		return FALSE;
	}
	prect->left = point.x;
	prect->top = point.y;

	point.x = prect->right;
	point.y = prect->bottom;
	if (!ScreenToClient(hwndDlg, &point)) {
		return FALSE;
	}
	prect->right = point.x;
	prect->bottom = point.y;
	return TRUE;
}
//
//
//
INT_PTR CALLBACK
WarningDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	CWarnDlg* pDlgWarn;
	PAINTSTRUCT ps;
	HDC hdc;
	RECT rect, rectDlg;
	HFONT hfont;
	int deltaY;
	switch (uMsg) {
	case WM_INITDIALOG:
		pDlgWarn = (CWarnDlg*)lParam;

		(void)SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);

		// Get screen coordinates of main dialog window
		GetWindowRect(hwndDlg, &rectDlg);

		// Get the original size of the text-box rectangle.
		GetClientRect(GetDlgItem(hwndDlg, IDC_MSG), &rect);

		// Calculate original height of the text-box rectangle
		deltaY = rect.bottom;

		// Get the device context
		hdc = GetDC(GetDlgItem(hwndDlg, IDC_MSG));
		// Need to select the right font to get the right result...
		hfont = (HFONT)SendMessage(GetDlgItem(hwndDlg, IDC_MSG), WM_GETFONT, 0, 0);
		SelectObject(hdc, hfont);
		// Size the dialog according to the message text.
		CAssert(DrawText(hdc, pDlgWarn->szMsg, -1, &rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL) != 0).Sys(MSG_SYSTEM_CALL, _T("WarningDlgProc [DrawText]")).Throw();
		ReleaseDC(GetDlgItem(hwndDlg, IDC_MSG), hdc);

		// Calculate the height decrease (if negative, increase) of the height (we do not change width)
		deltaY -= rect.bottom;

		// Set the size of the text box
		GetWindowRect(GetDlgItem(hwndDlg, IDC_MSG), &rect);
		WindowRectToClientRect(hwndDlg, &rect);
		rect.bottom -= deltaY;
		MoveWindow(GetDlgItem(hwndDlg, IDC_MSG), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, FALSE);

		// Move the checkbox up by the required delta
		GetWindowRect(GetDlgItem(hwndDlg, IDC_CHECKMSG), &rect);
		WindowRectToClientRect(hwndDlg, &rect);
		rect.top -= deltaY;
		rect.bottom -= deltaY;
		MoveWindow(GetDlgItem(hwndDlg, IDC_CHECKMSG), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, FALSE);

		// Move the OK-button up by the required delta
		GetWindowRect(GetDlgItem(hwndDlg, IDOK), &rect);
		WindowRectToClientRect(hwndDlg, &rect);
		rect.top -= deltaY;
		rect.bottom -= deltaY;
		MoveWindow(GetDlgItem(hwndDlg, IDOK), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, FALSE);

		// Move the Cancel-button up by the required delta
		GetWindowRect(GetDlgItem(hwndDlg, IDCANCEL), &rect);
		WindowRectToClientRect(hwndDlg, &rect);
		rect.top -= deltaY;
		rect.bottom -= deltaY;
		MoveWindow(GetDlgItem(hwndDlg, IDCANCEL), rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, FALSE);

		// Set the size of the dialog box itself
		GetWindowRect(hwndDlg, &rect);
		rect.bottom -= deltaY;
		MoveWindow(hwndDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, FALSE);

		SetDlgItemText(hwndDlg, IDC_MSG, pDlgWarn->szMsg);
		SetDlgItemText(hwndDlg, IDC_CHECKMSG, pDlgWarn->szNotAgainMsg);
		CheckDlgButton(hwndDlg, IDC_CHECKMSG, BST_UNCHECKED);

		{
			axpl::ttstring s = MainDlgTitleBar();
			SetWindowText(hwndDlg, s.c_str());
		}
		SetDlgItemText(hwndDlg, IDOK, CMessage().AppMsg(INF_IDOK).GetMsg());
		SetDlgItemText(hwndDlg, IDCANCEL, CMessage().AppMsg(INF_IDCANCEL).GetMsg());
		SetFocus(GetDlgItem(hwndDlg, IDOK));

		// Make sure it's on the desktop
		SendMessage(hwndDlg, DM_REPOSITION, 0, 0);

		return FALSE;

	case WM_PAINT:
		hdc = BeginPaint(hwndDlg, &ps);
		DrawIcon(hdc, 10, 10, LoadIcon(NULL, IDI_WARNING));
		EndPaint(hwndDlg, &ps);
		return FALSE;

	case WM_COMMAND:
	{
		pDlgWarn = (CWarnDlg*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
		switch (wParam) {
		case IDC_CHECKMSG:
			pDlgWarn->fNotAgain = IsDlgButtonChecked(hwndDlg, IDC_CHECKMSG);
			break;
		case IDOK:
			EndDialog(hwndDlg, IDOK);
			break;
		case IDCANCEL:
			EndDialog(hwndDlg, IDCANCEL);
			break;
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
}

//
//  Show a warning dialogue with message, an 'ok' button and a
//  'don't show this warning again' checkbox. Return the state
//  of the checkbox, and OK/Cancel response.
//
bool
WarningDlg(LPCTSTR szFileName, DWORD dwMsg, DWORD dwNotAgainMsg, BOOL& fNotAgain) {
	bool fOk = false;
	fNotAgain = FALSE;
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		CWarnDlg dlgWarn;

		dlgWarn.szMsg = CopySz(CMessage().Wrap(0).AppMsg(dwMsg, NULL, szFileName).GetMsg());
		dlgWarn.szNotAgainMsg = CopySz(CMessage().AppMsg(dwNotAgainMsg).GetMsg());
		dlgWarn.fNotAgain = fNotAgain;
		switch (DialogBoxParam(ghInstance,
			MAKEINTRESOURCE(IDD_WARNING),
			GetForegroundWindow(),
			WarningDlgProc,
			(LPARAM)&dlgWarn)) {
		case IDOK:
			fOk = true;
			break;
		case IDCANCEL:
			break;
		default:
			CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("WarningDlg()")).Throw();
		}
		fNotAgain = dlgWarn.fNotAgain;
	}
	else {
		CMessage().Wrap(0).AppMsg(dwMsg, NULL, szFileName).LogEvent(0);
	}
	return fOk;
}
//
//	The basic idea behind SafeEdit is to solve the problem of uncontrolled edit control
//	memory by simply not putting anything of interest there! We intercept the WM_CHAR
//	message and store it in our locally controlled buffer instead. That buffer is backed
//	by a memory mapped file, which thus never winds up in the swap file.
//
//	Still vulnerable to windows hooks and sniffers though...
//
LRESULT CALLBACK SafeEdit(
	HWND hwnd,      // handle to window
	UINT uMsg,      // message identifier
	WPARAM wParam,  // first message parameter
	LPARAM lParam   // second message parameter
) {
	SSafeEdit* pSafeEdit = (SSafeEdit*)(LONG_PTR)GetWindowLongPtr(hwnd, GWLP_USERDATA);
	WNDPROC lpfnOldWndProc = pSafeEdit->lpfnOldWndProc;
	switch (uMsg) {
	case WM_DESTROY:
		(void)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)lpfnOldWndProc);

		delete pSafeEdit;
		break;
	case WM_PASTE:
	case WM_CLEAR:
	case WM_COPY:
	case WM_CUT:
	case WM_UNDO:
	case WM_LBUTTONDBLCLK:
	case WM_RBUTTONDOWN:
		return TRUE;
	case WM_LBUTTONDOWN:
		SetFocus(hwnd);
		return TRUE;
	case WM_KEYDOWN:
		switch ((int)wParam) {
			// Quick and dirty way to make Ctrl-V work. It's hard to make
			// accelerators work in dialog-boxes, so lets forget it for now.
			// I (think...) it's pretty universal to use Ctrl+V as Paste...
		case 'V':
			if (GetKeyState(VK_CONTROL) < 0) {
				if (IsClipboardFormatAvailable(CF_TEXT)) {
					if (OpenClipboard(hwnd)) {
						HANDLE hClipData = GetClipboardData(CF_TEXT);
						if (hClipData) {
							const char* szClipData = (const char*)GlobalLock(hClipData);
							if (szClipData) {
								std::string allowedChars;
								const char* cp = szClipData;
								char c;
								while (c = *cp++) {
									// Remove disallowed chars, but do beep for each so as to emulate the behavior
									// of typing.
									if (strchr((const char*)szPassphraseChars, c) == NULL) {
										(void)MessageBeep(MB_OK);
									}
									else {
										allowedChars.push_back(c);
									}
								}
								GlobalUnlock(hClipData);
								// If we successfully got at least one char
								if (allowedChars.length() > 0) {
									PostMessage(hwnd, WM_USER, TRUE, 0);
									for (std::string::iterator it = allowedChars.begin(); it != allowedChars.end(); ++it) {
										PostMessage(hwnd, WM_CHAR, *it, 0);
									}
									PostMessage(hwnd, WM_USER, FALSE, 0);
								}
							}
						}
						CloseClipboard();
					}
				}
				return TRUE;
			}
			break;
		case VK_PRIOR:
		case VK_NEXT:
		case VK_HOME:
		case VK_LEFT:
		case VK_RIGHT:
		case VK_UP:
		case VK_DOWN:
		case VK_INSERT:
		case VK_DELETE:
			return TRUE;
		}
		break;
	case WM_USER:
		pSafeEdit->fIsPasting = (BOOL)wParam;
		return TRUE;
		break;
	case WM_CHAR:
		switch ((int)wParam) {
			// We only handle back-space of the non-printables.
		case 0x08:
			if (strlen(pSafeEdit->szPassphrase) > 0) {
				pSafeEdit->szPassphrase[strlen(pSafeEdit->szPassphrase) - 1] = '\0';
			}
			else {
				(void)MessageBeep(MB_OK);
				return TRUE;
			}
			break;
			// Ignore other non-printables
		case 0x0a:
		case 0x0d:
		case 0x16: // Ctrl-V... We might just catch it here too... Now we ignore it.
		case 0x1b:
		case 0x09:
			break;
			// Now we have a printable character.
		default:
			unsigned char cChar[2];	// Yes, really a character + nul. Nothing else but...
			// If the char is Unicode, we first translate it to Ansi.
			// If we're pasting, we already know the char is in Ansi.
			if (pSafeEdit->fIsWindowUnicode && !pSafeEdit->fIsPasting) {
				BOOL fUsedDefault;
				if (!WideCharToMultiByte(CP_ACP,
					WC_COMPOSITECHECK | WC_DEFAULTCHAR,
					(LPCWSTR)&wParam,
					1,
					(LPSTR)&cChar,
					2,
					NULL,
					&fUsedDefault) || fUsedDefault) {
					(void)MessageBeep(MB_OK);
					return TRUE;
				}
			}
			else {
				cChar[0] = (unsigned char)wParam;
			}
			if (strchr((const char*)szPassphraseChars, cChar[0]) == NULL || strlen(pSafeEdit->szPassphrase) == pSafeEdit->uiLen) {
				(void)MessageBeep(MB_OK);
				return TRUE;
			}
			strncat_s(pSafeEdit->szPassphrase, pSafeEdit->uiLen + 1, (const char*)&cChar, 1);
			wParam = *_T("*");
		}
		// Fall thru
	default:
		;
	}
	return CallWindowProc(lpfnOldWndProc, hwnd, uMsg, wParam, lParam);
}

//
//	Dialog procedure for the new passphrase dialog
//
INT_PTR CALLBACK NewPassphraseDlgProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
) {
	SDlgInfo* pDlgInfo;
	SSafeEdit* pSafeEdit;
	switch (uMsg) {
	case WM_INITDIALOG:
		pDlgInfo = (SDlgInfo*)lParam;

		SetDlgItemText(hwndDlg, IDC_TRYXECRETS, CMessage().AppMsg(INF_XECRETS_HYPERLINK).GetMsg());
		awl::IStaticHyperlink::GetInstance().EnableHyperlink(GetDlgItem(hwndDlg, IDC_TRYXECRETS));

		(void)SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);

		pSafeEdit = new SSafeEdit;
		ASSPTR(pSafeEdit);

		pSafeEdit->uiLen = MAX_PASSPHRASE_LEN;
		pSafeEdit->szPassphrase = new char[pSafeEdit->uiLen + 1];
		ASSPTR(pSafeEdit->szPassphrase);
		pSafeEdit->szPassphrase[0] = '\0';

		pSafeEdit->lpfnOldWndProc = (WNDPROC)(LONG_PTR)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1), GWLP_WNDPROC, (LONG_PTR)SafeEdit);

		pSafeEdit->fIsWindowUnicode = IsWindowUnicode(hwndDlg);
		pSafeEdit->fIsPasting = FALSE;

		(void)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1), GWLP_USERDATA, (LONG_PTR)pSafeEdit);

		pSafeEdit = new SSafeEdit;
		ASSPTR(pSafeEdit);

		pSafeEdit->uiLen = MAX_PASSPHRASE_LEN;
		pSafeEdit->szPassphrase = new char[pSafeEdit->uiLen + 1];
		ASSPTR(pSafeEdit->szPassphrase);
		pSafeEdit->szPassphrase[0] = '\0';

		pSafeEdit->lpfnOldWndProc = (WNDPROC)(LONG_PTR)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE2), GWLP_WNDPROC, (LONG_PTR)SafeEdit);

		pSafeEdit->fIsWindowUnicode = IsWindowUnicode(hwndDlg);
		pSafeEdit->fIsPasting = FALSE;

		(void)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE2), GWLP_USERDATA, (LONG_PTR)pSafeEdit);

		{
			CMessage message;
			SetDlgItemText(hwndDlg, IDC_ENTER_PASS, message.AppMsg(INF_ENTER_PASS).GetMsg());
			SetDlgItemText(hwndDlg, IDC_ENTER_VERIFY, message.AppMsg(INF_ENTER_VERIFY).GetMsg());
			SetDlgItemText(hwndDlg, IDC_KEYFILE, message.AppMsg(INF_FRAME_KEYFILE).GetMsg());
			SetDlgItemText(hwndDlg, IDOK, message.AppMsg(INF_IDOK).GetMsg());
			SetDlgItemText(hwndDlg, IDCANCEL, message.AppMsg(INF_IDCANCEL).GetMsg());

			if (!pDlgInfo->fDisableSaveInCache_E) {
				SetDlgItemText(hwndDlg, IDC_CHECKCACHE_E, CMessage().AppMsg(INF_SAVE_ENCKEY).GetMsg());
				CheckDlgButton(hwndDlg, IDC_CHECKCACHE_E, pDlgInfo->fSaveInCache_E ? BST_CHECKED : BST_UNCHECKED);
			}
			else {
				ShowWindow(GetDlgItem(hwndDlg, IDC_CHECKCACHE_E), SW_HIDE);
			}
			if (!pDlgInfo->fDisableSaveInCache_D) {
				SetDlgItemText(hwndDlg, IDC_CHECKCACHE_D, CMessage().AppMsg(INF_SAVE_DECKEY).GetMsg());
				CheckDlgButton(hwndDlg, IDC_CHECKCACHE_D, pDlgInfo->fSaveInCache_D ? BST_CHECKED : BST_UNCHECKED);
			}
			else {
				ShowWindow(GetDlgItem(hwndDlg, IDC_CHECKCACHE_D), SW_HIDE);
			}
		}

		{
			axpl::ttstring s = MainDlgTitleBar();
			SetWindowText(hwndDlg, s.c_str());
		}

		// Ensure that we are not obscured by parent, if possible.
		SetWindowPos(hwndDlg, IsParentTopMost(hwndDlg) ? HWND_TOPMOST : GetParent(hwndDlg), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetForegroundWindow(hwndDlg);
		CenterWindow(hwndDlg);
		SetFocus(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1));

		// Make sure it's on the desktop
		SendMessage(hwndDlg, DM_REPOSITION, 0, 0);

		return FALSE;

	case WM_COMMAND:
	{
		pDlgInfo = (SDlgInfo*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
		LPSTR szPhrase1 = ((SSafeEdit*)(LONG_PTR)GetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1), GWLP_USERDATA))->szPassphrase;
		LPSTR szPhrase2 = ((SSafeEdit*)(LONG_PTR)GetWindowLongPtr(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE2), GWLP_USERDATA))->szPassphrase;
		switch (wParam) {
		case IDC_CHECKCACHE_E:
			pDlgInfo->fSaveInCache_E = IsDlgButtonChecked(hwndDlg, IDC_CHECKCACHE_E);
			break;
		case IDC_CHECKCACHE_D:
			pDlgInfo->fSaveInCache_D = IsDlgButtonChecked(hwndDlg, IDC_CHECKCACHE_D);
			break;
		case IDC_BUTTONKEYBROWSE:
		{
			// Give a warning about what we're about to do
			CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeyFileUseInfo);
			BOOL fNotAgain = utRegWarn.GetDword(FALSE);
			if (!fNotAgain) {
				bool fOk = WarningDlg(_T(""), INF_KEYFILE_USE, INF_DONTREPEAT, fNotAgain);
				if (fNotAgain) {
					utRegWarn.SetDword(fNotAgain);
				}
				if (!fOk) {
					break;
				}
			}

			pDlgInfo->szKeyFileName = auto_ptr<_TCHAR>(AGetOpenFileNameDialog(hwndDlg, CMessage().AppMsg(INF_KEYFILE_NAME).GetMsg(), true));
			if (pDlgInfo->szKeyFileName.get()) {
				SetDlgItemText(hwndDlg, IDS_KEYFILENAME, pDlgInfo->szKeyFileName.get());
			}
		}
		break;
		case IDC_TRYXECRETS:
			::ShellExecute(hwndDlg, L"open", gszXecretsUrl, NULL, NULL, SW_SHOWNORMAL);
			break;
		case IDOK:
			if (strcmp(szPhrase1, szPhrase2) != 0) {
				CMessage(hwndDlg).AppMsg(MSG_NOTSAME).ShowWarning();
				SendDlgItemMessage(hwndDlg, IDC_NEWPASSPHRASE1, WM_SETTEXT, 0, (LPARAM)_T(""));
				SendDlgItemMessage(hwndDlg, IDC_NEWPASSPHRASE2, WM_SETTEXT, 0, (LPARAM)_T(""));
				*szPhrase1 = *szPhrase2 = (_TCHAR)0;
				SetFocus(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1));
				return FALSE;
			}
			// If we have not key-file and no passphrase, silenty just stay in place.
			// It's still possible to specify a zero-length key-file, but... If we really want
			// to we can check that elsewhere.
			if ((strlen(szPhrase1) == 0) && (!pDlgInfo->szKeyFileName.get() || !pDlgInfo->szKeyFileName.get()[0])) {
				SetFocus(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1));
				return FALSE;
			}
			// Check if the key-file appears to match the look of an Xecrets File-generated key-file
			if (pDlgInfo->szKeyFileName.get() && pDlgInfo->szKeyFileName.get()[0]) {
				// Check if we have a different length than expected
				HANDLE hFile = CreateFile(pDlgInfo->szKeyFileName.get(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
				DWORD cbFileSize = 0;
				if (hFile != INVALID_HANDLE_VALUE) {
					cbFileSize = GetFileSize(hFile, NULL);
					CloseHandle(hFile);
				}

				// Now, check that we have both the expected length, and the expected extension - if
				// either test fails, we give a warning (unless we've been told never to issue this warning,
				// or we're in server mode).
				_TCHAR* szExt = PathFindExtension(pDlgInfo->szKeyFileName.get());
				if (gcbAxCryptKeyFile != cbFileSize ||
					_tcsicmp(szExt, PathFindExtension(CMessage().AppMsg(INF_KEYFILE_NAME).GetMsg())) != 0) {
					// Give a warning that it appears that the user is about to use a non-standard file...
					CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeyFileNotEncrypt);
					BOOL fNotAgain = utRegWarn.GetDword(FALSE);
					// ...unless we've already been told not to issue this warning!
					if (!fNotAgain) {
						bool fOk = WarningDlg(_T(""), INF_KEYFILE_NOT_ENCRYPT, INF_DONTREPEAT, fNotAgain);
						if (fNotAgain) {
							utRegWarn.SetDword(fNotAgain);
						}
						// If this was not OK, let user try again
						if (!fOk) {
							SetFocus(GetDlgItem(hwndDlg, IDC_NEWPASSPHRASE1));
							return FALSE;
						}
					}
				}
			}
			pDlgInfo->szPassphrase = szPhrase1;
			delete[] szPhrase2;
			EndDialog(hwndDlg, TRUE);
			break;
		case IDCANCEL:
			delete[] szPhrase1;
			delete[] szPhrase2;
			EndDialog(hwndDlg, FALSE);
			break;
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
}
//
//	Dialog procedure for simple passphrase dialog
//
INT_PTR CALLBACK PassphraseDlgProc(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
) {
	SDlgInfo* pDlgInfo;
	SSafeEdit* pSafeEdit;
	switch (uMsg) {
	case WM_INITDIALOG:
		pDlgInfo = (SDlgInfo*)lParam;

		SetDlgItemText(hwndDlg, IDC_TRYXECRETS, CMessage().AppMsg(INF_XECRETS_HYPERLINK).GetMsg());
		awl::IStaticHyperlink::GetInstance().EnableHyperlink(GetDlgItem(hwndDlg, IDC_TRYXECRETS));

		(void)SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);

		pSafeEdit = new SSafeEdit;
		ASSPTR(pSafeEdit);

		pSafeEdit->uiLen = MAX_PASSPHRASE_LEN;
		pSafeEdit->szPassphrase = new char[pSafeEdit->uiLen + 1];
		ASSPTR(pSafeEdit->szPassphrase);
		pSafeEdit->szPassphrase[0] = '\0';

		pSafeEdit->lpfnOldWndProc = (WNDPROC)(LONG_PTR)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_PASSPHRASE), GWLP_WNDPROC, (LONG_PTR)SafeEdit);

		pSafeEdit->fIsWindowUnicode = IsWindowUnicode(hwndDlg);
		pSafeEdit->fIsPasting = FALSE;

		(void)SetWindowLongPtr(GetDlgItem(hwndDlg, IDC_PASSPHRASE), GWLP_USERDATA, (LONG_PTR)pSafeEdit);

		SetDlgItemText(hwndDlg, IDC_ENTER_PASS, CMessage().AppMsg(((SDlgInfo*)lParam)->IDDMainPrompt).GetMsg());
		SetDlgItemText(hwndDlg, IDC_KEYFILE, CMessage().AppMsg(INF_FRAME_KEYFILE).GetMsg());
		SetDlgItemText(hwndDlg, IDOK, CMessage().AppMsg(INF_IDOK).GetMsg());
		SetDlgItemText(hwndDlg, IDCANCEL, CMessage().AppMsg(INF_IDCANCEL).GetMsg());

		if (!pDlgInfo->fDisableSaveInCache_E) {
			SetDlgItemText(hwndDlg, IDC_CHECKCACHE_E, CMessage().AppMsg(INF_SAVE_ENCKEY).GetMsg());
			CheckDlgButton(hwndDlg, IDC_CHECKCACHE_E, pDlgInfo->fSaveInCache_E ? BST_CHECKED : BST_UNCHECKED);
		}
		else {
			ShowWindow(GetDlgItem(hwndDlg, IDC_CHECKCACHE_E), SW_HIDE);
		}
		if (!pDlgInfo->fDisableSaveInCache_D) {
			SetDlgItemText(hwndDlg, IDC_CHECKCACHE_D, CMessage().AppMsg(INF_SAVE_DECKEY).GetMsg());
			CheckDlgButton(hwndDlg, IDC_CHECKCACHE_D, pDlgInfo->fSaveInCache_D ? BST_CHECKED : BST_UNCHECKED);
		}
		else {
			ShowWindow(GetDlgItem(hwndDlg, IDC_CHECKCACHE_D), SW_HIDE);
		}

		SetWindowLong(GetDlgItem(hwndDlg, IDS_FILENAME), GWL_STYLE, (LONG)(LONG_PTR)GetWindowLongPtr(GetDlgItem(hwndDlg, IDS_FILENAME), GWL_STYLE) | SS_PATHELLIPSIS);
		if (pDlgInfo->szFileName && pDlgInfo->szFileName[0]) {
			SetDlgItemText(hwndDlg, IDS_FILENAME, pDlgInfo->szFileName);
		}
		else {
			ShowWindow(GetDlgItem(hwndDlg, IDS_FILENAME), SW_HIDE);
		}

		// Set style of Key File Name control
		SetWindowLong(GetDlgItem(hwndDlg, IDS_KEYFILENAME), GWL_STYLE, (LONG)(LONG_PTR)GetWindowLongPtr(GetDlgItem(hwndDlg, IDS_KEYFILENAME), GWL_STYLE) | SS_PATHELLIPSIS);

		{
			axpl::ttstring s = MainDlgTitleBar();
			SetWindowText(hwndDlg, s.c_str());
		}

		// Ensure that we are not obscured by parent, if possible.
		SetWindowPos(hwndDlg, IsParentTopMost(hwndDlg) ? HWND_TOPMOST : GetParent(hwndDlg), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetForegroundWindow(hwndDlg);
		CenterWindow(hwndDlg);
		SetFocus(GetDlgItem(hwndDlg, IDC_PASSPHRASE));

		// Make sure it's on the desktop
		SendMessage(hwndDlg, DM_REPOSITION, 0, 0);

		return FALSE;

	case WM_COMMAND:
	{
		pDlgInfo = (SDlgInfo*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
		LPSTR szPhrase = ((SSafeEdit*)(LONG_PTR)GetWindowLongPtr(GetDlgItem(hwndDlg, IDC_PASSPHRASE), GWLP_USERDATA))->szPassphrase;
		switch (LOWORD(wParam)) {
		case IDC_CHECKCACHE_E:
			pDlgInfo->fSaveInCache_E = IsDlgButtonChecked(hwndDlg, IDC_CHECKCACHE_E);
			break;
		case IDC_CHECKCACHE_D:
			pDlgInfo->fSaveInCache_D = IsDlgButtonChecked(hwndDlg, IDC_CHECKCACHE_D);
			break;
		case IDC_BUTTONKEYBROWSE:
			pDlgInfo->szKeyFileName = auto_ptr<_TCHAR>(AGetOpenFileNameDialog(hwndDlg, CMessage().AppMsg(INF_KEYFILE_NAME).GetMsg(), true));
			if (pDlgInfo->szKeyFileName.get()) {
				SetDlgItemText(hwndDlg, IDS_KEYFILENAME, pDlgInfo->szKeyFileName.get());
			}
			break;
		case IDC_TRYXECRETS:
			::ShellExecute(hwndDlg, L"open", gszXecretsUrl, NULL, NULL, SW_SHOWNORMAL);
			break;
		case IDOK:
			pDlgInfo->szPassphrase = szPhrase;
			EndDialog(hwndDlg, TRUE);
			break;
		case IDCANCEL:
			delete szPhrase;
			EndDialog(hwndDlg, FALSE);
			break;
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
}
/// \brief Prompt for a new passphrase and possibly a key-file.
/// \param szPassphrase The passphrase is returned here unless canceled.
/// \param szFileName The key-file file name if any is returned here.
/// \return true if one was gotten, false if user canceled etc.
bool
GetNewPassphrase(char** szPassphrase, TCHAR** szKeyFileName, HWND hWnd) {
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		SDlgInfo dlgInfo;
		CRegistry utRegSaveFlag_E(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey);
		CRegistry utRegSaveFlag_D(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey);

		DWORD dwDisableSaveEncryptionKey = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDisableSaveEncryptionKey).GetDword(0);
		dlgInfo.fDisableSaveInCache_E = dwDisableSaveEncryptionKey != 0;

		DWORD dwDisableSaveDecryptionKey = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDisableSaveDecryptionKey).GetDword(0);
		dlgInfo.fDisableSaveInCache_D = dwDisableSaveDecryptionKey != 0;

		dlgInfo.szPassphrase = NULL;
		dlgInfo.fSaveInCache_E = dlgInfo.fDisableSaveInCache_E ? FALSE : utRegSaveFlag_E.GetDword();
		dlgInfo.fSaveInCache_D = dlgInfo.fDisableSaveInCache_D ? FALSE : utRegSaveFlag_D.GetDword();
		dlgInfo.szKeyFileName = auto_ptr<_TCHAR>(NULL);

		switch (DialogBoxParam(
			ghInstance,
			MAKEINTRESOURCE(IDD_NEWPASSPHRASE),
			hWnd ? hWnd : GetForegroundWindow(),
			NewPassphraseDlgProc,
			(LPARAM)&dlgInfo)) {
		case TRUE: {
			utRegSaveFlag_E.SetDword(dlgInfo.fSaveInCache_E);
			utRegSaveFlag_D.SetDword(dlgInfo.fSaveInCache_D);
			if (dlgInfo.szPassphrase != NULL) {
				*szPassphrase = dlgInfo.szPassphrase;
				dlgInfo.szPassphrase = NULL;
			}
			if (dlgInfo.szKeyFileName.get() != NULL) {
				*szKeyFileName = dlgInfo.szKeyFileName.release();
			}
			return *szPassphrase != NULL;
		}
		case FALSE:
			return false;
		default:
			CMessage().AppMsg(MSG_INTERNAL_ERROR, _T("GetNewPassphrase()")).ShowError();
			return false;
		}
	}
	else {
		CMessage().Wrap(0).AppMsg(ERR_KEYPROMPT_SERVER_MODE).LogEvent(0);
		return false;
	}
}
//
//	Get a passphrase for an existing password. No verification here.
// Set szPassphrase and szKeyFileName to the result.
// Return false if cancel or no passphrase.
//
bool
GetPassphrase(int iPromptID, LPCTSTR szFileName, auto_ptr<char>& szPassphrase, auto_ptr<TCHAR>& szKeyFileName, HWND hWnd) {
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		SDlgInfo dlgInfo;
		CRegistry utRegSaveFlag_E(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey);
		CRegistry utRegSaveFlag_D(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey);

		DWORD dwDisableSaveEncryptionKey = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDisableSaveEncryptionKey).GetDword(0);
		dlgInfo.fDisableSaveInCache_E = dwDisableSaveEncryptionKey != 0;

		DWORD dwDisableSaveDecryptionKey = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDisableSaveDecryptionKey).GetDword(0);
		dlgInfo.fDisableSaveInCache_D = dwDisableSaveDecryptionKey != 0;

		dlgInfo.IDDMainPrompt = iPromptID;
		dlgInfo.szPassphrase = NULL;
		dlgInfo.fSaveInCache_E = dlgInfo.fDisableSaveInCache_E ? FALSE : utRegSaveFlag_E.GetDword();
		dlgInfo.fSaveInCache_D = dlgInfo.fDisableSaveInCache_D ? FALSE : utRegSaveFlag_D.GetDword();
		dlgInfo.szFileName = szFileName;
		dlgInfo.szKeyFileName = auto_ptr<_TCHAR>(NULL);

		switch (DialogBoxParam(ghInstance,
			MAKEINTRESOURCE(IDD_PASSPHRASE),
			hWnd ? hWnd : GetForegroundWindow(),
			PassphraseDlgProc,
			(LPARAM)&dlgInfo)) {
		case TRUE: {
			utRegSaveFlag_E.SetDword(dlgInfo.fSaveInCache_E);
			utRegSaveFlag_D.SetDword(dlgInfo.fSaveInCache_D);
			if (dlgInfo.szPassphrase != NULL) {
				szPassphrase = auto_ptr<char>(dlgInfo.szPassphrase);
			}
			if (dlgInfo.szKeyFileName.get() != NULL) {
				szKeyFileName = dlgInfo.szKeyFileName;
			}
			return szPassphrase.get() != NULL;
		}
		case FALSE:
			return false;
		default:
			CMessage().AppMsg(MSG_INTERNAL_ERROR, _T("GetPassphrase()")).ShowError();
			return false;
		}
	}
	else {
		CMessage().Wrap(0).AppMsg(ERR_KEYPROMPT_SERVER_MODE).LogEvent(0);
		return false;
	}
}