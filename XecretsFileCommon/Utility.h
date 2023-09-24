#ifndef	_UTILITY
#define	_UTILITY
/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
	Utility.h						Misc utility code and declarations etc.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
#include "shlobj.h"

#include <algorithm>
#include <string>

//
//  Minimal class to declare pointers to objects, that delete
//  themselves upon destruction, thereby minimizing risk of
//  leakage, especially during exceptions.
//
//  Important: Use as a regular pointer with two features:
//      1 - Autoinitialized to NULL
//      2 - Auto deletion on destruction.
//
//  Remember thus, if you delete manually, to set the pointer to
//  NULL! (As should be done anyway in good style). Otherwise you
//  get the deletion done twice.
//
#pragma warning(disable: 4284)
template<class T> class CPtrTo {
	T* m_p;
public:
	CPtrTo() { m_p = NULL/*new T*/; }
	CPtrTo(T* p) { m_p = p; }
	~CPtrTo() { if (m_p != NULL) delete m_p; }
	CPtrTo<T>& operator=(T* p) {
		if (m_p) delete m_p;
		m_p = p;
		return *this;
	}
	CPtrTo<T>& operator=(T& p) { *this = (T*)p; }
	T** operator&() { return &m_p; }
	operator T* () { return m_p; }
	T* operator ->() { return m_p; }
	T* rel() { T* p = m_p; m_p = NULL; }
};
#pragma warning(default: 4284)
//
//	A 'safe' HANDLE wrapping class, ensuring closing of handle on destruction.
//
//	As the windows-designers have decided in their infinite wisdom to have
//	many ways to represent a handle, such as int's, void *'s and struct *'s,
//	it turns out to be hard to do a generic HANDLE-template. This results.
//
//	Template arguments are:
//		Name of handle type
//		Name of return type from close handle,
//		Address of close handle function.
//
template<class T, class CloseT, CloseT(_stdcall* CloseFunc)(T)> class THandle {
	T m_h;
public:
	THandle() {
		m_h = T(-1);				// Always illegal
	}
	THandle(T h) { m_h = h; }
	~THandle() {
		if (IsValid()) Close();	// Ensure we do not double-close
	}
	THandle<T, CloseT, CloseFunc>& operator=(T h) {
		m_h = h;
		return *this;
	}
	operator T() { return m_h; }
	T* operator &() { return &m_h; }
	CloseT Close() {
		T h = m_h;
		m_h = T(-1);
		return (*CloseFunc)(h);		// Return the result of whatever type
	};
	BOOL IsValid() { return m_h != T(-1) && m_h != T(0); }
};

/// \brief A super-minimal helper class to handle auto-deletion of pointers to arrays.
template<class T> class CAutoArray {
	T* m_pa;
public:
	CAutoArray(T* p) {
		m_pa = p;
	}
	~CAutoArray() {
		delete[] m_pa;
	}
	T* Get() {
		return m_pa;
	}
};
//
//	Now define common handles as safe classes.
//
typedef class THandle<HANDLE, BOOL, &CloseHandle> CHandle;
typedef class THandle<HKEY, LONG, &RegCloseKey> CHKey;
typedef class THandle<HANDLE, BOOL, &CloseHandle> CHFile;
typedef class THandle<HANDLE, BOOL, &FindClose> CHFind;
typedef class THandle<HANDLE, BOOL, &FindCloseChangeNotification> CHChange;
typedef class THandle<HMODULE, BOOL, &FreeLibrary> CHModule;
typedef class THandle<HWND, BOOL, &DestroyWindow> CHWnd;
//
//	Helper class to make exceptions and critical sections work together,
//	the desctructor will always be called when leaving a context, thus
//	we ensure that we alse leave the critical section, even if an
//	exception occurs inside it.
//
class CCriticalSection {
private:
	CRITICAL_SECTION* m_pCriticalSection;
	BOOL m_fIsIn;
public:
	CCriticalSection(CRITICAL_SECTION* pCritSect, BOOL fStartState = FALSE) {
		m_pCriticalSection = pCritSect;
		if (fStartState) Enter();
		m_fIsIn = fStartState;
	}
	~CCriticalSection() {
		if (m_fIsIn) {
			Leave();
		}
	}
	void Enter() {
		EnterCriticalSection(m_pCriticalSection);
		m_fIsIn = TRUE;
	}
	void Leave() {
		m_fIsIn = FALSE;
		LeaveCriticalSection(m_pCriticalSection);
	}
};
//
//	Simple helper to XOR two memory blocks to a third.
//
inline void
XorMemory(void* dst, void* src1, void* src2, int len) {
	while (len--) *((char*&)(dst))++ = *((char*&)src1)++ ^ *((char*&)src2)++;
}
//
// This little sucker is a workaround for SetForegroundWindow that MS broke in 98/2K
//
inline void
MySetForegroundWindow(void) {
#ifdef _DEBUG
	if (GetForegroundWindow() == NULL) {
		MessageBox(NULL, _T("No foreground window!"), _T("XecretsFileClassic Debug"), MB_OK);
	}
#else
#endif
	CHWnd hWnd = CreateWindow(_T("STATIC"), _T(""), WS_POPUP, 0, 0, 0, 0, GetForegroundWindow(), NULL, GetModuleHandle(NULL), NULL);
	ShowWindow(hWnd, SW_NORMAL);
	SetFocus(hWnd);
	UpdateWindow(hWnd);
	DestroyWindow(hWnd);    // 2002-07-22 /SS - remove if problems
}

//
//  Simple allocators/duplicators
//
extern LPTSTR CopySz(LPCTSTR szSrc);
extern LPTSTR FormatSz(LPCTSTR szFormat, ...);

extern LPITEMIDLIST CopyPidl(IMalloc* pMalloc, LPCITEMIDLIST pidl);
extern WCHAR* CopySzWz(LPCSTR szIn);
extern LPSTR CopyWzSz(WCHAR* wzIn);

extern void DebugBox(LPTSTR szMsg);
extern HWND ForegroundWait(HWND hWnd, unsigned int iTimeOut);
extern void CenterWindow(HWND hwnd, bool fDesktop = false);

#endif  _UTILITY