/*
	@(#) $Id$

	The purpose of this class is to encapsulate functionality for dynamically
	allocating strings that is the result for printf-like functionality. I'm
	not sure how this should be done portably for a MacIntosh or Unix-platform...

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
	CFmtMsg.cpp                     Actions on temporary files and directories

	E-mail                          YYYY-MM-DD              Reason
	support@axantum.com             2002-10-07              Initial

*/
#include "stdafx.h"

#include    "CFmtMsg.h"

CFmtMsg::CFmtMsg(const TCHAR* szMsg, ...) : m_szFmtMsg(NULL) {
	va_list vaArgs;
	va_start(vaArgs, szMsg);
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_STRING,
		szMsg, 0, 0, (TCHAR*)&m_szFmtMsg, 0, &vaArgs);
	va_end(vaArgs);
}

CFmtMsg::CFmtMsg(CFmtMsg& fmtmsg) : m_szFmtMsg(NULL) {
	if (fmtmsg.m_szFmtMsg) {
		size_t ccFmtMsg = _tcslen(fmtmsg.m_szFmtMsg) + 1;
		m_szFmtMsg = (TCHAR*)LocalAlloc(0, ccFmtMsg * sizeof * m_szFmtMsg);
		_tcscpy_s(m_szFmtMsg, ccFmtMsg, fmtmsg.m_szFmtMsg);
	}
}

CFmtMsg::CFmtMsg(void) : m_szFmtMsg(NULL) {
}

void
CFmtMsg::Fmt(const TCHAR* szMsg, ...) {
	va_list vaArgs;
	va_start(vaArgs, szMsg);
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_STRING,
		szMsg, 0, 0, (TCHAR*)&m_szFmtMsg, 0, &vaArgs);
	va_end(vaArgs);
}

CFmtMsg::~CFmtMsg() {
	if (m_szFmtMsg) {
		LocalFree(m_szFmtMsg);
	}
}

TCHAR* CFmtMsg::Get() {
	if (m_szFmtMsg) {
		return m_szFmtMsg;
	}
	else {
		return _T("");
	}
}