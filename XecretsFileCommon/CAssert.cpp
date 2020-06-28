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
	CAssert.cpp						Exception and Message handling

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2001-12-23				Added logging support
									2002-02-11				Use CHKey in LogLevel to fix handle leak
									2002-08-11              Rel 1.2
*/
#include	"StdAfx.h"
#include	"CFileName.h"
#include	"CVersion.h"
#include    "CRegistry.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CAssert.cpp"
//
//  Depends on ghMsgModule and ghInstance to be initialized properly
//

CMessage::CMessage(HWND hWnd) : m_wMaxWidth(50) {
	m_hWnd = hWnd;
}

//
// Can't use __declspec(thread) static as it doesn't work well in delay loaded DLL's
//
//  The TLS index is TlsAlloc()'d once per process during run-time startup by
//  initializing the static. At the same time we register an atexit() function to
//  handle the TlsFee() of the TLS index.
//
static DWORD dwTlsIndex = TLS_OUT_OF_INDEXES;

static void FreeTls(void) {
	if (dwTlsIndex != TLS_OUT_OF_INDEXES) {
		TlsFree(dwTlsIndex);
	}
}

static void AllocTls(void) {
	if ((dwTlsIndex = TlsAlloc()) != TLS_OUT_OF_INDEXES) {
		atexit(FreeTls);
	}
	return;
}
//
//	Get a Msg from system or application message table,
//	with up to two arguments (or NULL).
//	The third argument is the previous message, if any.
//
//	Return the generated message.
//
CStrPtr
CMessage::Msg(DWORD dwFlag, DWORD dwMsgID, CStrPtr utStr1, CStrPtr utStr2) {
	// This is initialized once per process start/dll load, early.
	static long lAllocTls = 0;

	long l;
	do {
		switch (l = InterlockedExchange(&lAllocTls, 1)) {
		case 0:
			// First call by any thread, allocate the TLS index we need.
			AllocTls();
			InterlockedExchange(&lAllocTls, 2);
			break;
		case 1:
			// Race condition - retry.
			Sleep(10);
			break;
		case 2:
			// All is well. Restore.
			InterlockedExchange(&lAllocTls, 2);
		default:
			break;
		}
	} while (l == 1);   // Loop to avoid race condition.
	// The problem is that this code is used in many situations, both as a DLL
	// and as part of the main code, and it's sort of non-trivial to ensure that a
	// critical section object gets initalized before any thing executes which may
	// call this code. The whole purpose of the TLS exercise
	// here is anyway just to gracefully handle the situation with a double-exception,
	// which in turn is a rather rare event hopefully.

	// The TlsGetValue()/TlsSetValue() sequence here and below is by definition thread-safe,
	// as they access thread-local storage.
	// dwTlsIndex is only modified by AllocTls() above (and FreeTls()), so it's usage here
	// is also thread-safe.
	if (dwTlsIndex == TLS_OUT_OF_INDEXES) {
		return _T("Error - Out of TLS indexes. Cannot get message safely.");
	}
	else if (TlsGetValue(dwTlsIndex)) {
		return _T("Error - Double exception. Cannot get message.");
	}
	TlsSetValue(dwTlsIndex, (LPVOID)1);

	LPCTSTR aszArg[4];

	aszArg[0] = gszAxCryptExternalName;
	aszArg[1] = utStr1;
	aszArg[2] = utStr2;
	aszArg[3] = m_utMsg;

	LPTSTR szMsg;
	//
	//	Now, this should not really be that hard... But I can't make it work as I understand
	//	the documentation - someone please explain? I'm sure there is an explanation.
	//	Anyway - what I want is to have the following preference order:
	//	1 - Registry specified language (HKLM default after HKCU)
	//	2 - System Default Language
	//	3 - User selected language
	//	4 - Any
	//  Supposedly '0' as language ID in that parameter should most of the trick.
	//	But I can't get it to work. It always picks	US English. So I first try to force it
	//	using the System Default, then the thread locale, if that doesn't work,
	//	I let it pick up whatever it can find.
	//
	DWORD dwLanguageId = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValDefaultLanguageId).GetDword(0);
	if (!dwLanguageId) {
		dwLanguageId = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValDefaultLanguageId).GetDword(GetSystemDefaultLangID());
	}
	//
	//	Note to developers: Newer versions of the message compiler produces Unicode messages, there
	//	is no switch do disable this. This in turn, causes messages to be erroneously formatted.
	//	Currently Xecrets File is not Unicode-enabled, thus please use the old message compiler. The compiler
	//	may reside in for example Microsoft SDK\bin or Microsoft Visual Studio\VC98\bin. A good (for
	//	this purpose) version is dated 1998-04-20 and is named mc.exe.
	//
	if (!FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | dwFlag | FORMAT_MESSAGE_ARGUMENT_ARRAY | m_wMaxWidth,	// Max width of text
		ghMsgModule, dwMsgID, dwLanguageId,
		(LPTSTR)&szMsg, 0, (va_list*)aszArg)) {
		if (!FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | dwFlag | FORMAT_MESSAGE_ARGUMENT_ARRAY | m_wMaxWidth,	// Max width of text
			ghMsgModule, dwMsgID, (WORD)GetThreadLocale(),
			(LPTSTR)&szMsg, 0, (va_list*)aszArg)) {
			if (!FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | dwFlag | FORMAT_MESSAGE_ARGUMENT_ARRAY | m_wMaxWidth,	// Max width of text
				ghMsgModule, dwMsgID, 0,
				(LPTSTR)&szMsg, 0, (va_list*)aszArg)) {
				// Pretty catastrophic - can't even read the proper error message.
				TlsSetValue(dwTlsIndex, (LPVOID)0);
				return _T("Error - cannot read message definitions.");
			}
		}
	}
	// Sometimes trailing spaces cause trouble.
	_TCHAR* szEnd = &szMsg[_tcslen(szMsg)];
	while (szEnd > szMsg && iswspace(*--szEnd)) {
		*szEnd = '\0';
	}

	CStrPtr	utStrReturn = szMsg;						// Save the text
	(void)LocalFree(szMsg);						// Free system allocated memory.
	TlsSetValue(dwTlsIndex, (LPVOID)0);
	return utStrReturn;
}
//
//  Show a dialog, or if in server mode, log the message to the log-
//  file, and return the appropriate affirmative IDOK, IDYES, IDIGNORE, IDCANCEL etc.
//
int
CMessage::ShowDialog(UINT uiStyleMask) {
	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		//if (m_hWnd == NULL) MySetForegroundWindow();

		return MessageBox(
			//m_hWnd == NULL ? /*GetForegroundWindow()*/NULL/*<SS 2002-09-01 testing...>*/ : m_hWnd,
			NULL,
			m_utMsg,
			// Show version information depending on ShowNoVersion option, unless it's an error display in which case we always display the version
			CVersion().String(gfAxCryptShowNoVersion && ((uiStyleMask & MB_ICONERROR) == 0)),
			MB_TOPMOST | MB_SETFOREGROUND | uiStyleMask);
	}
	else {
		LogEvent(0);
		switch (uiStyleMask & MB_TYPEMASK) {
		case MB_OK:
		case MB_OKCANCEL:
			return IDOK;

		case MB_ABORTRETRYIGNORE:
			return IDIGNORE;

		case MB_YESNOCANCEL:
		case MB_YESNO:
			return IDYES;

		case MB_RETRYCANCEL:
			return IDCANCEL;

		default:
			return IDOK;
		}
	}
}
//
//	Return the log level in the registry, or zero if the key
//	does not exist.
/*static */ DWORD
CMessage::LogLevel() {
	return CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValEventLogLevel).GetDword(0);
}

CMessage&
CMessage::AppMsg(DWORD dwMsgID, CStrPtr utArg1, CStrPtr utArg2) {
	m_utMsg = Msg(FORMAT_MESSAGE_FROM_HMODULE, dwMsgID, utArg1, utArg2);
	return *this;
}

CMessage&
CMessage::AppMsg(DWORD dwMsgID, int iArg1, CStrPtr szArg2) {
	return AppMsg(dwMsgID, *CPtrTo<CStrPtr>(FmtInt(_T("%d"), iArg1)), szArg2);
}

CMessage&
CMessage::AppMsg(DWORD dwMsgID, CStrPtr szArg1, int iArg2) {
	return AppMsg(dwMsgID, szArg1, *CPtrTo<CStrPtr>(FmtInt(_T("%d"), iArg2)));
}

CMessage&
CMessage::AppMsg(DWORD dwMsgID, int iArg1, int iArg2) {
	return AppMsg(dwMsgID, *CPtrTo<CStrPtr>(FmtInt(_T("%d"), iArg1)), *CPtrTo<CStrPtr>(FmtInt(_T("%d"), iArg2)));
}

CStrPtr&
CMessage::GetMsg() {
	return m_utMsg;
}

CMessage&
CMessage::SysMsg(DWORD dwMsgID, CStrPtr utArg1, CStrPtr utArg2) {
	m_utMsg = Msg(FORMAT_MESSAGE_FROM_SYSTEM, dwMsgID, utArg1, utArg2);
	return *this;
}

CMessage&
CMessage::Wrap(WORD wMaxWidth) {
	if (wMaxWidth) {
		m_wMaxWidth = wMaxWidth;
	}
	else {
		m_wMaxWidth = FORMAT_MESSAGE_MAX_WIDTH_MASK;
	}
	return *this;
}

int
CMessage::ShowError(UINT uiStyleMask) {
	return ShowDialog(uiStyleMask | MB_ICONERROR);
}

int
CMessage::ShowInfo(UINT uiStyleMask) {
	return ShowDialog(uiStyleMask | MB_ICONINFORMATION);
}

int
CMessage::ShowWarning(UINT uiStyleMask) {
	return ShowDialog(uiStyleMask | MB_ICONWARNING);
}

int
CMessage::ShowQuestion(UINT uiStyleMask) {
	return ShowDialog(uiStyleMask | MB_ICONQUESTION);
}
void
CMessage::LogEvent(DWORD dwLogLevel) {
	if (LogLevel() >= dwLogLevel) {
		CFileName utLogFile;

		utLogFile.SetPath2SysTempDir();

		utLogFile.SetDir(CStrPtr(utLogFile.GetDir()) + CStrPtr(_T("\\")));
		utLogFile.SetName(gszAxCryptInternalName);
		utLogFile.SetExt(_T(".log"));
		HANDLE hLogFile = CreateFile(utLogFile.Get(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hLogFile == INVALID_HANDLE_VALUE) {
			// Here we should probably do something smart to hande an error, but
			// we can't just throw the exception, as we risk infinite recursion
			// and other bad things.
			return;
		}
		CAssert(SetFilePointer(hLogFile, 0, NULL, FILE_END) != 0xffffffff).Sys().Throw();

		DWORD dwBytesWritten;
		TCHAR szDateTime[100];
		SYSTEMTIME stLocalTime;
		GetLocalTime(&stLocalTime);
		_stprintf_s(szDateTime, sizeof szDateTime / sizeof szDateTime[0], _T("%04d-%02d-%02d %02d.%02d.%02d "), stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay, stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond);
		(void)WriteFile(hLogFile, szDateTime, (DWORD)(_tcslen(szDateTime) * sizeof TCHAR), &dwBytesWritten, NULL);

		// Quick & dirty remove '\r' and '\n' from the message.
		CPtrTo<TCHAR> szOneLine = CopySz(m_utMsg);
		int iSpaceCount = 0;
		TCHAR* pIn, * pOut;
		// It is guaranteed that the output is not longer than the input
		for (pIn = pOut = szOneLine; *pIn; pIn++) {
			switch (*pIn) {
			case _T('\r'):
			case _T('\n'):
			case _T('\t'):
				if (!iSpaceCount) iSpaceCount = 1;
				break;
			case _T(' '):
				iSpaceCount++;
				break;
			default:
				if (iSpaceCount) {
					do {
						*pOut++ = _T(' ');
					} while (--iSpaceCount);
				}
				*pOut++ = *pIn;
			}
		}
		*pOut = _T('\0');

		(void)WriteFile(hLogFile, szOneLine, (DWORD)(_tcslen(szOneLine) * sizeof TCHAR), &dwBytesWritten, NULL);
		(void)WriteFile(hLogFile, _T("\r\n"), (DWORD)(_tcslen(_T("\r\n")) * sizeof TCHAR), &dwBytesWritten, NULL);
		(void)CloseHandle(hLogFile);
	}
}

// Must be deleted by caller...
CStrPtr*
CMessage::FmtInt(LPCTSTR szFmt, int iInt) {
	const int strSize = 40;
	CStrPtr* pszStr = new CStrPtr(strSize);			// Should be enough...
	ASSPTR((TCHAR*)pszStr);
	(void)_stprintf_s(*pszStr, strSize, szFmt, iInt);
	return pszStr;
}

//
//	Default constructor
//
CAssert::CAssert() {
}
//
//	Copy constructor
//
CAssert::CAssert(CAssert& utError) {
	m_bOk = utError.m_bOk;
	m_dwLastError = utError.m_dwLastError;
	m_utMsg = utError.m_utMsg;
}
//
//	The normally called constructor.
//
CAssert::CAssert(BOOL bOk) {
	m_bOk = bOk;
	m_dwLastError = GetLastError();
}
//
//  Alternate for other error code sources than GetLastError()
//
CAssert::CAssert(BOOL bOk, DWORD dwError) {
	m_bOk = bOk;
	m_dwLastError = dwError;
}
//
//	Display a proper message box for a ready formatted message.
//
CAssert&
CAssert::Show() {
	m_utMsg.ShowError();
	return *this;
}
//
//	Get the actual message so far.
//
CStrPtr&
CAssert::GetMsg() {
	return m_utMsg.GetMsg();
}
//
//	Get the last error code to the caller.
//
DWORD
CAssert::LastError() {
	return m_dwLastError;
}
//
//	Throw an exception...
//
void
CAssert::Throw() {
	if (!m_bOk) {
		// Now this is tricky... When we throw an exception, the CAssert
		// object contains dynamically allocated memory, thus we must
		// adjust for a leak here.
		HEAP_CHECK_BEGIN(_T("CAssert::Throw()"), TRUE);
		throw* this;
		HEAP_CHECK_END
	}
}
//
//	Generate application error msg, MsgID
//	%2 = N/A
//	%3 = szCtx
//	%4 = Previous message, if any
//
CAssert&
CAssert::App(DWORD dwMsgID, LPCTSTR szCtx) {
	if (!m_bOk) {
		m_utMsg.AppMsg(dwMsgID, NULL, szCtx);
		m_dwLastError = dwMsgID;						// Remember the Alamo
	}
	return *this;
}
//
//	Generate system error directly from GetLastError()
//	%2 = N/A
//	%3 = N/A
//	%4 = Previous message, if any
//
CAssert&
CAssert::Sys() {
	if (!m_bOk) m_utMsg.SysMsg(m_dwLastError);
	return *this;
}
//
// Generate system error msg from MsgID
//	%2 = LastError = %2
//	%3 = szCtx = %3
//	%4 = Previous message, if any
//
CAssert&
CAssert::Sys(DWORD dwMsgID, LPCTSTR szCtx) {
	if (!m_bOk) {
		m_utMsg.AppMsg(
			dwMsgID,
			CMessage().SysMsg(m_dwLastError).GetMsg(),
			szCtx);
		m_dwLastError = dwMsgID;						// Remember the Alamo
	}
	return *this;
}
//
//	Generate application file error, using msgID
//	%2 = LastError
//	%3 = szFile
//	%4 = Previous message, if any
//
CAssert&
CAssert::File(DWORD dwMsgID, LPCTSTR szFile) {
	if (!m_bOk) {
		m_utMsg.AppMsg(
			dwMsgID,
			CMessage().SysMsg(m_dwLastError).GetMsg(),
			CFileName(szFile).GetTitle());
		m_dwLastError = dwMsgID;						// Remember the Alamo
	}
	return *this;
}

CAssert&
CAssert::File(LPCTSTR szFile) {
	if (!m_bOk) {
		m_utMsg.SysMsg(m_dwLastError, CFileName(szFile).GetTitle());
	}
	return *this;
}