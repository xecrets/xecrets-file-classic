/*
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
	Utility.cpp						Various context-free utility functions.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2002-08-05				Rel 1.2	Initial
									2002-08-16              RegCloseKey instead of CloseHandle
															Additional functions in CRegistry

*/
#include	"StdAfx.h"
//#include    <stdio.h>
#include    <stdarg.h>

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "Utility.cpp"

LPTSTR CopySz(LPCTSTR szSrc) {
	if (szSrc == NULL) return NULL;
	size_t ccDst = _tcslen(szSrc) + 1;
	LPTSTR szDst = new TCHAR[ccDst];
	ASSPTR(szDst);

	_tcscpy_s(szDst, ccDst, szSrc);
	return szDst;
}
//
//  Return an allocated formatted string, please remember to delete.
//
LPTSTR FormatSz(LPCTSTR szFormat, ...) {
	va_list argPtr;
	va_start(argPtr, szFormat);
	LPTSTR szFormattedValue;

	CAssert(FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		szFormat,
		0,
		0,
		(LPTSTR)&szFormattedValue,
		0,
		&argPtr)).Sys(MSG_SYSTEM_CALL, _T("FormatSz() [FormatMessage()]")).Throw();
	va_end(argPtr);
	LPTSTR szReturn = CopySz(szFormattedValue);
	// First free the buffer, then assert...
	LocalFree(szFormattedValue);

	return szReturn;
}

static UINT GetSizePidl(LPCITEMIDLIST pidl) {
	UINT cbTotal = 0;
	if (pidl != NULL) {
		while (pidl->mkid.cb) {
			cbTotal += pidl->mkid.cb;
			pidl = (LPCITEMIDLIST)((BYTE*)pidl + pidl->mkid.cb);
		}
		cbTotal += sizeof pidl->mkid.cb;    // Room for zero count too.
	}
	return cbTotal;
}

LPITEMIDLIST CopyPidl(IMalloc* pMalloc, LPCITEMIDLIST pidl) {
	UINT cb = 0;

	// Calculate size of list.
	cb = GetSizePidl(pidl);

	LPITEMIDLIST pidlRet = (LPITEMIDLIST)pMalloc->Alloc(cb);
	CAssert(pidlRet != NULL).App(MSG_MEMORY_ALLOC, _T("CopyPidl [Alloc()]")).Throw();
	CopyMemory(pidlRet, pidl, cb);
	return pidlRet;
}

WCHAR*
CopySzWz(LPCSTR szIn) {
	if (szIn == NULL) return NULL;

	int iLen = MultiByteToWideChar(CP_ACP, 0, szIn, -1, NULL, 0);
	WCHAR* wzOut = new WCHAR[iLen];
	ASSPTR(wzOut);

	MultiByteToWideChar(CP_ACP, 0, szIn, -1, wzOut, iLen);
	return wzOut;
}

LPSTR
CopyWzSz(WCHAR* wzIn) {
	if (wzIn == NULL) return NULL;

	int iLen = WideCharToMultiByte(CP_ACP, 0, wzIn, -1, NULL, 0, NULL, NULL);
	char* szOut = new char[iLen];
	ASSPTR(szOut);

	WideCharToMultiByte(CP_ACP, 0, wzIn, -1, szOut, iLen, NULL, NULL);
	return szOut;
}

void DebugBox(LPTSTR szMsg) {
	(void)MessageBox(NULL, szMsg, AXPRODUCTFILENAME _T(" Debug Message"), MB_OK);
}
//
//  Wait for the foreground window to change from the given window,
//  at most iTimeOut ms.
/// \param hWnd The previous foreground window to detect change from
/// \return The new foreground window - or NULL if  no change or no foreground
//
HWND ForegroundWait(HWND hWnd, unsigned int iTimeOut) {
	iTimeOut /= 10;                    // Wait in 10ms increments.

	HWND hNewWnd;
	while ((hNewWnd = GetForegroundWindow()) == hWnd && iTimeOut--) {
		Sleep(10);
	}
	return hNewWnd != hWnd ? hNewWnd : NULL;
}

void CenterWindow(HWND hwnd, bool fDesktop) {
	RECT rectWnd;
	RECT rectCenterIn;
	HWND hwndCenterIn;
	int nX, nY;
	int nParentWidth, nParentHeight, nWndWidth, nWndHeight;

	// Get a handle for the parent window, if any
	if ((hwndCenterIn = GetParent(hwnd)) != NULL) {
		ASSAPI(GetWindowRect(hwndCenterIn, &rectCenterIn));

		// Check and see if we're on the virtual screen desktop without explicitly knowing it.
		if (!fDesktop) {
			RECT rectVirtualScreen;
			rectVirtualScreen.left = GetSystemMetrics(SM_XVIRTUALSCREEN);
			rectVirtualScreen.right = rectVirtualScreen.left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
			rectVirtualScreen.top = GetSystemMetrics(SM_YVIRTUALSCREEN);
			rectVirtualScreen.bottom = rectVirtualScreen.top + GetSystemMetrics(SM_CYVIRTUALSCREEN);

			// These virtual screen calls are not supported on NT. It's seen by zero-return, no extended
			// error is available. So if we get all zeroes, we just ignore it.
			if (rectVirtualScreen.left || rectVirtualScreen.bottom || rectVirtualScreen.right || rectVirtualScreen.top) {
				fDesktop = memcmp(&rectVirtualScreen, &rectCenterIn, sizeof(RECT)) == 0;
			}
		}
	}

	// Get the bounding rectangles for the windows
	// Take multiple monitors into account.
	ASSAPI(GetWindowRect(hwnd, &rectWnd));
	if (fDesktop || hwndCenterIn == NULL) {
		// If we have no parent, or are on the desktop, use the physical monitor
		// instead.

		// Get the nearest monitor to the current mouse position
		POINT pt;
		ASSAPI(GetCursorPos(&pt));
		HMONITOR hMonitor = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);

		MONITORINFO mi;
		ZeroMemory(&mi, sizeof mi);
		mi.cbSize = sizeof mi;
		// get the work area or entire monitor rect.
		ASSAPI(GetMonitorInfo(hMonitor, &mi));
		rectCenterIn = mi.rcMonitor;
	}

	// Compute the new location of the window
	nParentWidth = rectCenterIn.right - rectCenterIn.left;
	nParentHeight = rectCenterIn.bottom - rectCenterIn.top;
	nWndWidth = rectWnd.right - rectWnd.left;
	nWndHeight = rectWnd.bottom - rectWnd.top;
	nX = rectCenterIn.left + ((nParentWidth - nWndWidth) / 2);
	nY = rectCenterIn.top + ((nParentHeight - nWndHeight) / 2);

	// If we're centering in a regular window, do not allow negative coordinates...
	// ... but if we're centering on the desktop on a monitor we need to allow this.
	if (!fDesktop && hwndCenterIn != NULL) {
		nX = max(0, nX);
		nY = max(0, nY);
	}

	// Move the window to its new location
	ASSAPI(SetWindowPos(hwnd, HWND_TOP, nX, nY, 0, 0, SWP_NOSIZE));
}