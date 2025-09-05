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
	PropertySheet.cpp				IShellPropSheetExt implementation

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
#include	"StdAfx.h"
#include	"../XecretsFileCommon/CAssert.h"
#include	"../XecretsFileCommon/CVersion.h"
//
//	Specifies an application-defined callback function that a property sheet
//	calls when a page is created and when it is about to be destroyed.
//	An application can use this function to perform initialization and
//	cleanup operations for the page.
//
//	The return value depends on the value of uMsg.
//	hWnd
//		Reserved; must be NULL.
//	uMsg
//		Action flag. This parameter can be one of the following values:
//			PSPCB_CREATE	A page is being created. Return nonzero to allow
//							the page to be created, or zero to prevent it.
//			PSPCB_RELEASE	A page is being destroyed. The return value is ignored.
//
//	ppsp
//		Address of a PROPSHEETPAGE structure that defines the page being
//		created or destroyed.
//
UINT CALLBACK
PropPageCallback(HWND hWnd, UINT uMsg, LPPROPSHEETPAGE  ppsp) {
	switch (uMsg) {
	case PSPCB_CREATE:
		return TRUE;

	case PSPCB_RELEASE:
		if (ppsp->lParam) {
			((LPCSHELLEXT)(ppsp->lParam))->Release();
		}
		return TRUE;
	}
	return TRUE;
}
//
//	Standard DialogProc
//
//	Return:
//		Except in response to the WM_INITDIALOG message, the dialog box procedure
//		should return nonzero if it processes the message, and zero if it does not.
//
INT_PTR CALLBACK
PropPageDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	// Pickup pointer to our property sheet page structure that
	// we save in in the WM_INITDIALOG
	LPPROPSHEETPAGE psp = (LPPROPSHEETPAGE)(LONG_PTR)GetWindowLongPtr(hDlg, DWLP_USER);
	LPCSHELLEXT lpcs;
	// If not before WM_INITDIALOG, fix CShellExt ptr.
	if (psp != NULL) {
		lpcs = (LPCSHELLEXT)psp->lParam;
	}

	switch (uMsg) {
	case WM_INITDIALOG:
		// Save lParam, i.e. PROPSHEETPAGE structure ptr provided by
		// the shell.
		// This is to handle a compiler problem with warnings when using the 64-bit compatible defines
#pragma warning ( push )
#pragma warning ( disable : 4244 )
		SetWindowLongPtr(hDlg, DWLP_USER, lParam);
#pragma warning ( pop )

		// These may be needed, are normally setup at the top, but we are too early.
		psp = (LPPROPSHEETPAGE)lParam;
		lpcs = (LPCSHELLEXT)psp->lParam;
		SetDlgItemText(hDlg, IDC_ENC_LEAD, CMessage().AppMsg(INF_ENC_LEAD).GetMsg());
		SetDlgItemText(hDlg, IDC_COMP_LEAD, CMessage().AppMsg(INF_COMP_LEAD).GetMsg());
		SetDlgItemText(hDlg, IDC_AUTH_LEAD, CMessage().AppMsg(INF_AUTH_LEAD).GetMsg());
		SetDlgItemText(hDlg, IDC_RAND_LEAD, CMessage().AppMsg(INF_RAND_LEAD).GetMsg());
		SetDlgItemText(hDlg, IDC_ENC, CMessage().AppMsg(INF_ENC).GetMsg());
		SetDlgItemText(hDlg, IDC_COMP, CMessage().AppMsg(INF_COMP).GetMsg());
		SetDlgItemText(hDlg, IDC_AUTH, CMessage().AppMsg(INF_AUTH).GetMsg());
		SetDlgItemText(hDlg, IDC_RAND, CMessage().AppMsg(INF_RAND).GetMsg());
		SetDlgItemText(hDlg, IDC_ABOUT_GROUP, CVersion(ghInstance).String());
		SetDlgItemText(hDlg, IDC_ABOUT, CMessage().Wrap(0).AppMsg(INF_ABOUT, CStrPtr(CVersion(ghInstance).LegalCopyright())).GetMsg());
		break;

	case WM_DESTROY:
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case 0: // Dummy to get rid of warning
		default:
			break;
		}
		break;

	case WM_NOTIFY:
		switch (((NMHDR FAR*)lParam)->code) {
		case PSN_SETACTIVE:
			break;

		case PSN_APPLY:
			// OK or Apply - do something.
			break;

		default:
			break;
		}
		break;

	default:
		return FALSE;
	}
	return TRUE;
}
//
//	Adds one or more pages to a property sheet that the shell displays
//	for a file object. When it is about to display the property sheet,
//	the shell calls this method for each property sheet handler
//	registered to the file type.
//
//	Returns NOERROR if successful, or an OLE-defined error value otherwise.
//
//	lpfnAddPage
//		Address of a function that the property sheet handler calls to
//		add a page to the property sheet. The function takes a property
//		sheet handle returned by the CreatePropertySheetPage function and
//		the lParam parameter passed to the AddPages method.
//	lParam
//		Parameter to pass to the function specified by the lpfnAddPage method.
//
//	For each page the property sheet handler needs to add to a property sheet,
//	the handler fills a PROPSHEETPAGE structure, calls the CreatePropertySheetPage
//	function, and then calls the function specified by the lpfnAddPage parameter.
//
STDMETHODIMP
CShellExt::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam) {
	PROPSHEETPAGE psp;
	HPROPSHEETPAGE hPage;

	HRESULT hRes = S_OK;
	try {
		if (m_pSelection->ShowPropertySheet()) {
			// Create the property sheet page
			psp.dwSize = sizeof psp;// no extra data.
			psp.dwFlags = PSP_USEREFPARENT | PSP_USETITLE | PSP_USECALLBACK;
			psp.hInstance = ghInstance;
			psp.pszTemplate = MAKEINTRESOURCE(IDD_DIALOG1);
			psp.hIcon = 0;
			psp.pszTitle = gszAxCryptExternalName;
			psp.pfnDlgProc = PropPageDlgProc;
			psp.pcRefParent = (UINT*)&glRefThisDLL;
			psp.pfnCallback = PropPageCallback;
			psp.lParam = (LPARAM)this;

			AddRef();
			hPage = CreatePropertySheetPage(&psp);
			if (hPage) {
				if (!lpfnAddPage(hPage, lParam)) {
					DestroyPropertySheetPage(hPage);
					Release();
					hRes = E_FAIL;
				}
			}
		}
	}
	catch (TAssert utErr) {
		utErr.Show();
		hRes = E_FAIL;
	}
	return hRes;
}
//
//	Replaces a page in a property sheet for a Control Panel object.
//
//	Returns NOERROR if successful, or an OLE-defined error value otherwise.
//
//	uPageID
//		Identifier of the page to replace. The values for this parameter
//		for Control Panels can be found in the Cplext.h header file.
//	lpfnReplacePage
//		Address of a function that the property sheet handler calls to replace
//		a page to the property sheet. The function takes a property sheet handle
//		returned by the CreatePropertySheetPage function and the lParam parameter
//		passed to the ReplacePage method.
//	lParam
//		Parameter to pass to the function specified by the lpfnReplacePage
//		parameter.
//
//	To replace a page, a property sheet handler fills a PROPSHEETPAGE structure,
//	calls CreatePropertySheetPage, and then calls the function specified
//	by lpfnReplacePage.
//
STDMETHODIMP
CShellExt::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplaceWith, LPARAM lParam) {
	// We are not a control panel...
	return E_FAIL;
}