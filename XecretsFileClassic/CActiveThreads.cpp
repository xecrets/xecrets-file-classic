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
	CActiveThreads.cpp				Keep track of threads so we can exit cleanly.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
#include	"StdAfx.h"
#include	"CActiveThreads.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

static volatile LONG unique_internal_id = 0;
//
// Create an object with a new thread so as to keep track of them.
//
CActiveThreads::CActiveThreads(CActiveThreads*& pRoot, HANDLE hThread, DWORD dwThreadId) {
	m_pNext = pRoot;
	pRoot = this;
	m_hThread = hThread;
	m_dwThreadId = dwThreadId;
	m_dwUniqueInternalId = (DWORD)InterlockedIncrement(&unique_internal_id);
}
//
// Destructor
//
CActiveThreads::~CActiveThreads() {
	CAssert(CloseHandle(m_hThread)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle() [CActiveThreads::~CActiveThreads()]")).Throw();
}
//
//	Remove a given thread, if it is there.
//
void
CActiveThreads::Remove(CActiveThreads*& pRoot, DWORD dwUniqueInternalId) {
	CActiveThreads** ppPrevNext = &pRoot;
	while (*ppPrevNext != NULL) {
		if ((*ppPrevNext)->m_dwUniqueInternalId == dwUniqueInternalId) {
			CActiveThreads* pToDelete = *ppPrevNext;
			*ppPrevNext = pToDelete->m_pNext;
			pToDelete->m_pNext = NULL;
			delete pToDelete;
			return;
		}
		else {
			ppPrevNext = &(*ppPrevNext)->m_pNext;
		}
	}
}
//
//	Just return the thread handle
//
HANDLE
CActiveThreads::Thread() {
	return m_hThread;
}

DWORD
CActiveThreads::ThreadId() {
	return m_dwThreadId;
}

DWORD
CActiveThreads::UniqueInternalId() {
	return m_dwUniqueInternalId;
}

//
//	Next pointer
//
CActiveThreads*
CActiveThreads::Next() {
	return m_pNext;
}