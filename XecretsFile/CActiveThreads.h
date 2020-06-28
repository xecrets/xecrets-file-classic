#ifndef	_CACTIVETHREADS
#define	_CACTIVETHREADS
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
	CActiveThreads.h				Keep track of threads so we can exit cleanly.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
//
// CActiveThreads is used to record the current threads of the
// master instance, to ensure that they are properly waited for
// at termination, and to store the appropriate keys.
//
class CActiveThreads {
	CActiveThreads* m_pNext;
	HANDLE m_hThread;
	DWORD m_dwThreadId;
	DWORD m_dwUniqueInternalId;
public:
	CActiveThreads(CActiveThreads*& pRoot, HANDLE hThread, DWORD dwThreadId);
	~CActiveThreads();
	void Remove(CActiveThreads*& pRoot, DWORD dwUniqueInternalId);
	HANDLE Thread();
	DWORD ThreadId();
	DWORD UniqueInternalId();
	CActiveThreads* Next();
};
#endif	_CACTIVETHREADS