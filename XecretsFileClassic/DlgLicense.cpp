/*! \file
	\brief License Dialog

	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2023 Svante Seleborg/Axon Data, All rights reserved.

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
*/
#include "StdAfx.h"
#include "../XecretsFileCommon/CVersion.h"
#include "../XecretsFileCommon/CRegistry.h"
#include "Dialog.h"

//
//	Arguments to dialog box.
//
struct SLicDlgInfo {
	string sLicensee;                       // Licensee always Ansi, for better or worse
	axpl::ttstring sSignature;              // Signature was always Ansi (although now we handle Unicode)
	bool fIsWindowUnicode;                  // Keep track if we're Unicode
};

//
//	Dialog procedure for the new passphrase dialog
//
INT_PTR CALLBACK DlgProcLicense(
	HWND hwndDlg,  // handle to dialog box
	UINT uMsg,     // message
	WPARAM wParam, // first message parameter
	LPARAM lParam  // second message parameter
) {
	SLicDlgInfo* pLicDlgInfo;
	switch (uMsg) {
	case WM_INITDIALOG:
		pLicDlgInfo = (SLicDlgInfo*)lParam;
		// This is to handle a compiler problem with warnings when using the 64-bit compatible defines
#pragma warning ( push )
#pragma warning ( disable : 4244 )
		(void)SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)lParam);
#pragma warning ( pop )

		pLicDlgInfo->fIsWindowUnicode = !!IsWindowUnicode(hwndDlg);

		ShowWindow(GetDlgItem(hwndDlg, IDC_BADLIC), SW_HIDE);
		ShowWindow(GetDlgItem(hwndDlg, IDC_ERRICON), SW_HIDE);

		SetDlgItemText(hwndDlg, IDC_ENTER_LICENSEE, CMessage().AppMsg(INF_ENTER_LICENSEE).GetMsg());
		SetDlgItemText(hwndDlg, IDC_ENTER_SIGNATURE, CMessage().AppMsg(INF_ENTER_SIGNATURE).GetMsg());
		SetDlgItemText(hwndDlg, IDOK, CMessage().AppMsg(INF_IDOK).GetMsg());
		SetDlgItemText(hwndDlg, IDCANCEL, CMessage().AppMsg(INF_IDCANCEL).GetMsg());
		SetDlgItemText(hwndDlg, IDC_LICENSEE, axpl::s2t(pLicDlgInfo->sLicensee).c_str());
		SetDlgItemText(hwndDlg, IDC_SIGNATURE, pLicDlgInfo->sSignature.c_str());
		SetDlgItemText(hwndDlg, IDC_BADLIC, CMessage().AppMsg(INF_BADLIC).GetMsg());
		SendDlgItemMessage(hwndDlg, IDC_SIGNATURE, WM_SETFONT, (WPARAM)(HFONT)GetStockObject(ANSI_FIXED_FONT), TRUE);

		{
			axpl::ttstring s = MainDlgTitleBar();
			SetWindowText(hwndDlg, s.c_str());
		}

		// Ensure that we are not obscured by parent, if possible.
		SetWindowPos(hwndDlg, IsParentTopMost(hwndDlg) ? HWND_TOPMOST : GetParent(hwndDlg), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		SetForegroundWindow(hwndDlg);
		//SetWindowPos(GetParent(hwndDlg), hwndDlg, 0, 0, 0, 0, SWP_NOSIZE|SWP_NOMOVE);

		// We always center the license dialog in the center of the screen, one reason
		// being that it may have the START-bar as it's parent, and centering around that
		// is not a very good thing.
		CenterWindow(hwndDlg, true);
		SetFocus(GetDlgItem(hwndDlg, IDC_LICENSEE));
		return FALSE;

	case WM_COMMAND:
	{
		pLicDlgInfo = (SLicDlgInfo*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
		_TCHAR szLicensee[250], szSignature[50];
		bool fChange = false;
		switch (LOWORD(wParam)) {
		case IDC_LICENSEE:
		case IDC_SIGNATURE:
			if (HIWORD(wParam) == EN_CHANGE) {
				ShowWindow(GetDlgItem(hwndDlg, IDC_BADLIC), SW_HIDE);
				ShowWindow(GetDlgItem(hwndDlg, IDC_ERRICON), SW_HIDE);
			}
			return FALSE;
			break;
		case IDOK:
			::GetDlgItemText(hwndDlg, IDC_LICENSEE, szLicensee, sizeof szLicensee);
			fChange = fChange || !TTStringCompareIgnoreCase(axpl::s2t(pLicDlgInfo->sLicensee), szLicensee);
			::GetDlgItemText(hwndDlg, IDC_SIGNATURE, szSignature, sizeof szSignature);
			fChange = fChange || !TTStringCompareIgnoreCase(pLicDlgInfo->sSignature, szSignature);

			if (fChange) {
				if (gpLicMgr->AddChkType(_TT("Full"), szLicensee, szSignature)) {
					pLicDlgInfo->sLicensee = axpl::t2s(std::wstring(szLicensee));
					pLicDlgInfo->sSignature = szSignature;
					EndDialog(hwndDlg, TRUE);
					break;
				}
				else {
					ShowWindow(GetDlgItem(hwndDlg, IDC_BADLIC), SW_SHOW);
					ShowWindow(GetDlgItem(hwndDlg, IDC_ERRICON), SW_SHOW);
					break;
				}
			}
			// If OK with no change - this we return as a 'Cancel'
			EndDialog(hwndDlg, FALSE);
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
/// \brief Prompt for a new passphrase and possibly a key-file.
/// \param szPassphrase The passphrase is returned here unless cancelled.
/// \param szFileName The key-file file name if any is returned here.
/// \return true if one was gotten, false if user cancelled etc.
ttstringpair
GetLicenseeSignature(HWND hWnd) {
	// If we're not running any licenses at all, we'll just return empty-handed.
	if (gpLicMgr == NULL) {
		return ttstringpair(_TT(""), _TT(""));
	}

	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		SLicDlgInfo dlgInfo;

		ttstringpair spLicense = gpLicMgr->GetType(_TT("Full"));
		dlgInfo.sLicensee = axpl::t2s(spLicense.first);
		dlgInfo.sSignature = spLicense.second;

		switch (DialogBoxParam(
			ghInstance,
			MAKEINTRESOURCE(IDD_LICENSE),
#ifdef _DEBUG
			hWnd,
#else
			// This screws up the debugger
			hWnd ? hWnd : GetForegroundWindow(),
#endif
			DlgProcLicense,
			(LPARAM)&dlgInfo)) {
		case TRUE: {
			// We should only be here if the dialog says something changed and
			// it's a valid license. Regardless of where we got any original license
			// that we displayed - we update the current user with this info. Most
			// likely this means the user has upgraded.
			CRegistry regKey(HKEY_CURRENT_USER, gszAxCryptRegKey);

			// Update the product activation info in the registry
			regKey.Value(szRegValLicensee).SetSz(axpl::s2t(dlgInfo.sLicensee).c_str());
			regKey.Value(szRegValSignature).SetSz(dlgInfo.sSignature.c_str());

			// We also want to display the activation menu, regardless of previous state.
			regKey.Value(szRegValShowActivationMenu).SetDword(TRUE);

			// Find the name of the restrictions as we want to refer to them
			const XNode* pRestrictXML = gpConfig->GetElementXML(gpConfig->GetConfigXML(), _TT("restrictions"));
			// Reapply terms, now with potentially a new valid license
			ApplyTerms(pRestrictXML);

			return ttstringpair(axpl::s2t(dlgInfo.sLicensee), dlgInfo.sSignature);
		}
		case FALSE:
			return ttstringpair(axpl::s2t(dlgInfo.sLicensee), dlgInfo.sSignature);
		default:
			CMessage().AppMsg(MSG_INTERNAL_ERROR, _T("GetLicenseeSignature()")).ShowError();
			return ttstringpair(_TT(""), _TT(""));
		}
	}
	else {
		CMessage().Wrap(0).AppMsg(ERR_KEYPROMPT_SERVER_MODE).LogEvent(0);
		return ttstringpair(_TT(""), _TT(""));
	}
}