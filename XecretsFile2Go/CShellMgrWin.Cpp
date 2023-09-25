/*! \file
	\brief CShellMgrWin.cpp - The Windows implementation of XecretsFile2Go

	This code builds heavily on the sample code distributed with Windows Template Library,
	which does not name any contributor or author, nor specify any kind of restrictions of
	use. Whilst this particular file is in this form licensed under GNU GPL as per below,
	this is not an attempt to claim authorship of that original code. The intention is only
	to protect the modified work as it is published here.

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Xecrets File Classic for the road.

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-08-06              Initial
\endverbatim
*/

#include "stdafx.h"

#include <shlobj.h>
#include <strsafe.h>

#include "CShellMgrWin.h"
#include "CDialogsWin.h"
#include "XecretsFile2GoWin.h"

#include "CMainFrameWin.h"
#include "EncDecWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CShellMgrWin.cpp"

int
CShellMgr::GetIconIndex(LPITEMIDLIST lpi, UINT uFlags) {
	SHFILEINFO sfi = { 0 };
	DWORD_PTR dwRet = ::SHGetFileInfo((LPCTSTR)lpi, 0, &sfi, sizeof(SHFILEINFO), uFlags);
	return (dwRet != 0) ? sfi.iIcon : -1;
}

void
CShellMgr::GetNormalAndSelectedIcons(LPITEMIDLIST lpifq, LPTVITEM lptvitem) {
	int nRet = lptvitem->iImage = GetIconIndex(lpifq, SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
	ATLASSERT(nRet >= 0);
	nRet = lptvitem->iSelectedImage = GetIconIndex(lpifq, SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_OPENICON);
	ATLASSERT(nRet >= 0);
}

LPITEMIDLIST
CShellMgr::ConcatPidls(LPCITEMIDLIST pidl1, LPCITEMIDLIST pidl2) {
	UINT cb1 = 0;
	if (pidl1 != NULL) {   // May be NULL
		cb1 = GetSize(pidl1) - sizeof(pidl1->mkid.cb);
	}

	UINT cb2 = GetSize(pidl2);

	LPITEMIDLIST pidlNew = (LPITEMIDLIST)::CoTaskMemAlloc(cb1 + cb2);
	if (pidlNew != NULL) {
		if (pidl1 != NULL) {
			memcpy(pidlNew, pidl1, cb1);
		}

		memcpy(((LPSTR)pidlNew) + cb1, pidl2, cb2);
	}

	return pidlNew;
}

BOOL
CShellMgr::GetName(LPSHELLFOLDER lpsf, LPITEMIDLIST lpi, DWORD dwFlags, LPTSTR lpFriendlyName, size_t cbFriendlyName) {
	BOOL bSuccess = TRUE;
	STRRET str = { STRRET_CSTR };

	if (lpsf->GetDisplayNameOf(lpi, dwFlags, &str) == NOERROR) {
		USES_CONVERSION;

		switch (str.uType) {
		case STRRET_WSTR:
			ASSCHK(SUCCEEDED(StringCbCopy(lpFriendlyName, cbFriendlyName, W2CT(str.pOleStr))), _T("StringCbCopy() failed"));
			::CoTaskMemFree(str.pOleStr);
			break;
		case STRRET_OFFSET:
			ASSCHK(SUCCEEDED(StringCbCopy(lpFriendlyName, cbFriendlyName, (LPTSTR)lpi + str.uOffset)), _T("StringCbCopy() failed"));
			break;
		case STRRET_CSTR:
			ASSCHK(SUCCEEDED(StringCbCopy(lpFriendlyName, cbFriendlyName, A2CT(str.cStr))), _T("StringCbCopy() failed"));
			break;
		default:
			bSuccess = FALSE;
			break;
		}
	}
	else {
		bSuccess = FALSE;
	}

	return bSuccess;
}

LPITEMIDLIST
CShellMgr::Next(LPCITEMIDLIST pidl) {
	LPSTR lpMem = (LPSTR)pidl;
	lpMem += pidl->mkid.cb;
	return (LPITEMIDLIST)lpMem;
}

UINT
CShellMgr::GetSize(LPCITEMIDLIST pidl) {
	UINT cbTotal = 0;
	if (pidl != NULL) {
		cbTotal += sizeof(pidl->mkid.cb);   // Null terminator
		while (pidl->mkid.cb != NULL) {
			cbTotal += pidl->mkid.cb;
			pidl = Next(pidl);
		}
	}

	return cbTotal;
}

LPITEMIDLIST
CShellMgr::CopyITEMID(LPITEMIDLIST lpi) {
	LPITEMIDLIST lpiTemp = (LPITEMIDLIST)::CoTaskMemAlloc(lpi->mkid.cb + sizeof(lpi->mkid.cb));
	::CopyMemory((PVOID)lpiTemp, (CONST VOID*)lpi, lpi->mkid.cb + sizeof(lpi->mkid.cb));
	return lpiTemp;
}

LPITEMIDLIST
CShellMgr::GetFullyQualPidl(LPSHELLFOLDER lpsf, LPITEMIDLIST lpi) {
	TCHAR szBuff[MAX_PATH] = { 0 };

	if (!GetName(lpsf, lpi, SHGDN_FORPARSING, szBuff, sizeof szBuff)) {
		return NULL;
	}

	HRESULT hr;
	CComPtr<IShellFolder> spDeskTop;
	hr = ::SHGetDesktopFolder(&spDeskTop);
	if (FAILED(hr)) {
		return NULL;
	}

	ULONG ulEaten = 0;
	LPITEMIDLIST lpifq = NULL;
	//ULONG ulAttribs = 0;
	USES_CONVERSION;
	hr = spDeskTop->ParseDisplayName(NULL, NULL, T2W(szBuff), &ulEaten, &lpifq, NULL);
	//hr = spDeskTop->ParseDisplayName(NULL, NULL, T2W(szBuff), &ulEaten, &lpifq, &ulAttribs);

	if (FAILED(hr)) {
		return NULL;
	}

	return lpifq;
}

DWORD CShellMgr::WorkerEncrypt(WorkerThreadParam* pParam) {
	HWND hWnd = pParam->hWndParent;
	LPSHELLFOLDER lpsfParent = pParam->lpsf;
	LPITEMIDLIST lpi = pParam->lpi;
	//POINT point = pParam->point;

	_TCHAR szBuf[MAX_PATH];
	if (GetName(lpsfParent, lpi, SHGDN_FORPARSING, szBuf, sizeof szBuf)) {
		_TCHAR szFolder[MAX_PATH];
		ASSCHK(SUCCEEDED(StringCbCopy(szFolder, sizeof szFolder, szBuf)), _T("StringCbCopy() failed"));
		ASSCHK(PathRemoveFileSpec(szFolder), _T("PathRemoveFileSpec() did not find a file name to remove"));

		CAxCryptEncryptWin2Go XecretsFile2Go(hWnd, &pParam->m_DlgProgress);
		if (!XecretsFile2Go.Encrypt(szBuf, szFolder)) {
			if (XecretsFile2Go.GetErrorCode() != AXCL_E_CANCEL) {
				::MessageBox(hWnd, XecretsFile2Go.GetError().c_str(), CConfig::ShortProductName().c_str(), MB_OK);
			}
		}
	}
	return 0;
}

DWORD CShellMgr::WorkerDecrypt(WorkerThreadParam* pParam) {
	HWND hWnd = pParam->hWndParent;
	LPSHELLFOLDER lpsfParent = pParam->lpsf;
	LPITEMIDLIST lpi = pParam->lpi;
	//POINT point = pParam->point;

	_TCHAR szBuf[MAX_PATH];
	if (GetName(lpsfParent, lpi, SHGDN_FORPARSING, szBuf, sizeof szBuf)) {
		_TCHAR szFolder[MAX_PATH];
		ASSCHK(SUCCEEDED(StringCbCopy(szFolder, sizeof szFolder, szBuf)), _T("StringCbCopy() failed"));
		ASSCHK(PathRemoveFileSpec(szFolder), _T("PathRemoveFileSpec() did not find a file name to remove"));

		CAxCryptDecryptWin2Go XecretsFile2Go(hWnd, &pParam->m_DlgProgress);
		if (!XecretsFile2Go.Decrypt(szBuf, szFolder)) {
			if (XecretsFile2Go.GetErrorCode() != AXCL_E_CANCEL) {
				::MessageBox(hWnd, XecretsFile2Go.GetError().c_str(), CConfig::ShortProductName().c_str(), MB_OK);
			}
		}
	}

	return 0;
}

/* static */ DWORD
CShellMgr::Worker(WorkerThreadParam* pParam) {
	HWND hWnd = pParam->hWndParent;
	LPSHELLFOLDER lpsfParent = pParam->lpsf;
	LPITEMIDLIST lpi = pParam->lpi;
	//POINT point = pParam->point;

	DWORD nRet = 1;
	// stuff like .zip-files are flagged as both folders and streams, so we check that and if it
	// is a stream in the file-system, we guess that it is a file after all - not a folder
	// The documentation is very unclear of the rgfInOut parameter. It appears to state that it's
	// an input parameter specifying the requested attrbutes - in fact it's provably not. When
	// set to zero, the function still returns attributes, at least for a single object.
	// The value returned is supposedly the attributes that are valid for all objects in the provided list.
	const ULONG rgfMask = SFGAO_FOLDER | SFGAO_FILESYSTEM | SFGAO_STREAM;
	ULONG rgf = rgfMask;
	HRESULT hr = lpsfParent->GetAttributesOf(1, const_cast<LPCITEMIDLIST*>(&lpi), &rgf);
	ASSCOM(hr);
	rgf &= rgfMask;
	switch (rgf) {
	case SFGAO_FOLDER | SFGAO_FILESYSTEM | SFGAO_STREAM:
	case SFGAO_FILESYSTEM | SFGAO_STREAM:
	case SFGAO_FILESYSTEM:
	{
		// This must be just about the trickiest syntax today! Anyway, what it means is, call the member-function
		// pointed to by pWorkerFunction, with 'this' set to the value of the pShellMgr ptr, and pass the appropriate
		// argument.
		nRet = (pParam->pShellMgr->*(pParam->pWorkerFunction))(pParam);
	}
	break;
	default:
		break;
	}

	// Finalize by sending a request to destroy the progresswindow. This will cross a thread-boundary, but that's
	// the whole point - the progress window is owned by the parent window, which runs in a different thread and which
	// has a nice message loop.
	SendMessage(hWnd, WM_USER_DESTROYPROGRESS, 0, reinterpret_cast<LPARAM>(pParam));
	return nRet;
}

void
CShellMgr::WorkerDispatch(TWorkerFunctionPtr pWorkerFunction, HWND hWnd, LPSHELLFOLDER lpsfParent, LPITEMIDLIST lpi, POINT point) {
	// This get's deleted by the RemoveThread function in the main thread.
	WorkerThreadParam* pParam = new WorkerThreadParam;
	lpsfParent->AddRef();
	pParam->hWndParent = hWnd;
	pParam->lpsf = lpsfParent;
	pParam->lpi = CopyITEMID(lpi);
	pParam->point = point;
	pParam->pWorkerFunction = pWorkerFunction;
	pParam->pShellMgr = this;
	pParam->ThreadFunc = Worker;

	PostMessage(hWnd, WM_USER_WORKERTHREAD, 0, reinterpret_cast<LPARAM>(pParam));
}

BOOL
CShellMgr::DoContextMenu(HWND hWnd, LPSHELLFOLDER lpsfParent, LPITEMIDLIST lpi, POINT point) {
	CComPtr<IContextMenu> spContextMenu;
	HRESULT hr = lpsfParent->GetUIObjectOf(hWnd, 1, const_cast<LPCITEMIDLIST*>(&lpi), IID_IContextMenu, 0, reinterpret_cast<void**>(&spContextMenu));
	ASSCOM(hr);

	HMENU hMenuPopup = ::CreatePopupMenu();
	ASSAPI(hMenuPopup != NULL);

	UINT indexMenu = 0;
	UINT idCmdFirst = 1;
	UINT idCmdEncrypt, idCmdDecrypt;
	InsertMenu(hMenuPopup, indexMenu++, MF_STRING | MF_BYPOSITION, idCmdEncrypt = idCmdFirst++, _("ShellMgr|ContextMenu|Encrypt"));
	InsertMenu(hMenuPopup, indexMenu++, MF_STRING | MF_BYPOSITION, idCmdDecrypt = idCmdFirst++, _("ShellMgr|ContextMenu|Decrypt"));
	InsertMenu(hMenuPopup, indexMenu++, MF_SEPARATOR | MF_BYPOSITION, 0, NULL);

	UINT idCmdShellFirst = idCmdFirst = 100;
	ASSCOM(hr = spContextMenu->QueryContextMenu(hMenuPopup, indexMenu, idCmdShellFirst, 0x7fff, CMF_NORMAL | CMF_EXPLORE));
	idCmdFirst = HRESULT_CODE(hr);

	UINT idCmd = ::TrackPopupMenu(hMenuPopup, TPM_LEFTALIGN | TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, hWnd, NULL);

	// If something was choosen...
	if (idCmd != 0) {
		if (idCmd == idCmdEncrypt) {
			WorkerDispatch(&CShellMgr::WorkerEncrypt, hWnd, lpsfParent, lpi, point);
		}
		else if (idCmd == idCmdDecrypt) {
			WorkerDispatch(&CShellMgr::WorkerDecrypt, hWnd, lpsfParent, lpi, point);
		}
		else {
			// Execute the command that was selected.
			CMINVOKECOMMANDINFOEX cmi = { 0 };
			cmi.cbSize = sizeof cmi;

			cmi.fMask = CMIC_MASK_UNICODE | CMIC_MASK_PTINVOKE;
			if (GetKeyState(VK_CONTROL) < 0) {
				cmi.fMask |= CMIC_MASK_CONTROL_DOWN;
			}
			if (GetKeyState(VK_SHIFT) < 0) {
				cmi.fMask |= CMIC_MASK_SHIFT_DOWN;
			}

			cmi.hwnd = hWnd;

			// We're primarily Unicode, but some may not support that so we place the verb in the Ansi-part too
			cmi.lpVerb = MAKEINTRESOURCEA(idCmd - idCmdShellFirst);
			cmi.lpVerbW = MAKEINTRESOURCEW(idCmd - idCmdShellFirst);
			cmi.ptInvoke = point;
			cmi.nShow = SW_SHOWNORMAL;
			hr = spContextMenu->InvokeCommand(reinterpret_cast<CMINVOKECOMMANDINFO*>(&cmi));
			ASSCOM(hr);
		}
	}

	::DestroyMenu(hMenuPopup);

	return TRUE;
}