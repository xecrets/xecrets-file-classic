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
	CStrPtr.cpp						Simple special purpose "standard" string class, mostly
									to facilitate proper 'delete's of new'd strings.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
#include	"StdAfx.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CStrPtr.cpp"
/*
	Simple "standard" string class, the main purpose here being
	ease of use with exceptions. Needing to keep track of new/delete
	is tedious at best. C++ supports stack unwinding, so here I
	define a simple object that will have it's destructor called
	whenever appropriate, thus minimizing the risks of memory
	leakage.

	The class consists of some functions and a data member that
	is a pointer to a dynamically allocated string buffer,
	managed by the class using proper copy-semantics.
*/
//
//	Empty string - NULL ptr
//
CStrPtr::CStrPtr() {
	m_szStr = NULL;
}
//
//	Reserve space for n TCHAR's
//
CStrPtr::CStrPtr(int iSiz) {
	m_szStr = NULL;
	if (iSiz) {
		m_szStr = new TCHAR[iSiz];
		ASSPTR(m_szStr);
	}
}
//
//	Copy constructor, make a true copy, i.e. copy the data into
//	a new buffer, don't just copy the pointer.
//
CStrPtr::CStrPtr(CStrPtr& utStr) {
	m_szStr = NULL;
	*this = utStr;
}
//
//	Copy the data pointed to into a new buffer, don't just copy
//	the pointer.
//
CStrPtr::CStrPtr(LPCTSTR szStr) {
	m_szStr = NULL;
	*this = szStr;
}
//
//	Destruction implies deletion, that was the whole point...
//
CStrPtr::~CStrPtr() {
	if (m_szStr != NULL) delete m_szStr;
}
//
//	Simplify usage by defining the casting operator to return
//	the actual pointer. Use this with care - don't keep this
//	pointer around!
//
CStrPtr::operator LPTSTR() {
	return m_szStr;
}
//
CStrPtr::operator LPCTSTR() {
	return m_szStr;
}
//
//	Another variant
//
CStrPtr::operator BYTE* () {
	return (BYTE*)m_szStr;
}
//
//	Proper copy-assignment, copying data, not pointers.
//
CStrPtr&
CStrPtr::operator= (LPCTSTR szStr) {
	if (m_szStr != NULL) delete m_szStr;
	if (szStr != NULL) {
		size_t ccStr = _tcslen(szStr) + 1;
		m_szStr = new TCHAR[ccStr];
		ASSPTR(m_szStr);

		_tcscpy_s(m_szStr, ccStr, szStr);
	}
	else {
		m_szStr = NULL;
	}
	return *this;
}
//
//	Proper copy-assignment, copying data, not pointers.
//
CStrPtr&
CStrPtr::operator= (CStrPtr& utStr) {
	return *this = (LPTSTR)utStr;
}
//
//	Concatenate...
//
CStrPtr&
CStrPtr::operator +(CStrPtr& utStr) {
	size_t ccNew = _tcslen(m_szStr) + _tcslen(utStr.m_szStr) + 1;
	LPTSTR szNew = new TCHAR[ccNew];
	ASSPTR(m_szStr);

	_tcscpy_s(szNew, ccNew, m_szStr);
	_tcscat_s(szNew, ccNew, utStr.m_szStr);
	delete[] m_szStr;
	m_szStr = szNew;
	return *this;
}
//
//	Return a 'permanent' pointer to the data, removing the
//	objects pointer. The caller takes over responsibility
//	to 'delete' the allocated buffer! Use with care.
//
LPTSTR
CStrPtr::Ptr() {
	LPTSTR szTmp = m_szStr;
	m_szStr = NULL;
	return szTmp;
}