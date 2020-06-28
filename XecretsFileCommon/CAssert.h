#ifndef	_CASSERT
#define	_CASSERT
/*
    @(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2020 Svante Seleborg/Axon Data, All rights reserved.

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
	CAssert.h						Messages and Assertions

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include	"CStrPtr.h"
#include	"stdio.h"
/*
	Assertions and Exceptions

	These are the major parts of the functionality:

	- Initial exception throwing - Generating a context-less message.
	- Message formatting/building - Adding context to the message.
	- Re-throwing the exception OR
	- Message display

	Typical usage is to create an Assert-object, with the assertion
	as the constructor argument, calling a message generating function
	directly, which also throws the exception.

	When catching the exception, typical usage is to build context in
	the message and/or re-throw and/or display and thus stop the
	process of re-throwing. Once displayed, the error should be
	considered handled and not re-thrown.

*/
extern CHModule ghMsgModule;
//
//	The base-class
//
class CMessage {
	HWND m_hWnd;
	CStrPtr m_utMsg;
	WORD m_wMaxWidth;

	CStrPtr Msg(DWORD dwFlag, DWORD dwMsgID, CStrPtr utArg1 = NULL, CStrPtr Arg2 = NULL);
public:
	CMessage(HWND hWnd = NULL);
	static DWORD LogLevel();
	CMessage& AppMsg(DWORD dwMsgID, CStrPtr utArg1 = NULL, CStrPtr Arg2 = NULL);
	CMessage& AppMsg(DWORD dwMsgID, int iArg1, CStrPtr szArg2 = NULL);
	CMessage& AppMsg(DWORD dwMsgID, CStrPtr szArg1, int iArg2);
	CMessage& AppMsg(DWORD dwMsgID, int iArg1, int iArg2);
	CMessage& SysMsg(DWORD dwMsgID, CStrPtr utArg1 = NULL, CStrPtr Arg2 = NULL);
	CMessage& Wrap(WORD wMaxWidth);
	CStrPtr& GetMsg();
	int ShowError(UINT uiStyleMask = MB_OK);
	int ShowInfo(UINT uiStyleMask = MB_OK);
	int ShowWarning(UINT uiStyleMask = MB_OK);
	int ShowQuestion(UINT uiStyleMask = MB_OK);
	int ShowDialog(UINT uiStyleMask = MB_OK);
	void LogEvent(DWORD dwLogLevel = 1);		// Force a log message with level 0.
private:
	CStrPtr *FmtInt(LPCTSTR szFmt, int iInt);
};

class CAssert {
public:
	CAssert();									// Default
	CAssert(CAssert& utError);					// Copy constructor
	CAssert(BOOL bOk);      					// Normally used for CAssertion.
    CAssert(BOOL bOk, DWORD dwError);           // Alternate for other errors.
//
	CAssert& App(DWORD dwMsgID, LPCTSTR szCtx = NULL);// Generate Msg, szCtx = %2
	CAssert& Sys();									// Generate LastError
	CAssert& Sys(DWORD dwMsgID, LPCTSTR szCtx = NULL);// Generate Msg, LastError = %2, szCtx = %3
	CAssert& File(LPCTSTR szFile);				// Generate Sys Msg. szFile = %3
	CAssert& File(DWORD dwMsgID, LPCTSTR szFile);	// Generate Msg, LastError = %2, szFile = %3
//
	CAssert& Show();	// Display a message box.
	CStrPtr& GetMsg();
    CMessage& Message() { return m_utMsg; }
	void Throw();								// Throw an exception.
	DWORD LastError();							// Return last error code.
protected:
//
	BOOL m_bOk;									// Saved from CAssertion constructor
	DWORD m_dwLastError;						// Saved in case of need from CAssertion
	CMessage m_utMsg;							// The message as such
};
//
//  Special purpose class to simplify checking of memory allocation errors. The problem
//  here is that we're in real trouble, so we'll just use a MessageBox and abort.
//
/*
class CMemAss : public CAssert {
public:
    CMemAss(void *p, LPTSTR szCtx = _T("?")) : CAssert(p != NULL) {
        if (!m_bOk) {
            // quick and very dirty, but no buffer overflows here!
            static TCHAR msgBuf[200], msgCtx[100];
            strncpy(msgCtx, szCtx, sizeof msgCtx);
            msgCtx[sizeof msgCtx - 1] = '\0';

            _stprintf(msgBuf, "Out of Memory in %s. Please report.", szCtx);
            MessageBox(NULL, msgBuf, gszAxCryptExternalName, MB_OK|MB_ICONSTOP);
            exit(1);
        }
    }
};
*/
//
// Convenient helper for system calls etc that do not
// set LastError
//
class CAssertEq : public CAssert {
public:
    inline CAssertEq(LONG lRes, LONG lOkRes) : CAssert(lRes == lOkRes, lRes) {}
};
//
typedef CAssert TAssert;
#endif	_CASSERT