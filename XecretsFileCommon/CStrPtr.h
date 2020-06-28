#ifndef	_CSTRPTR
#define	_CSTRPTR
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
	CStrPtr.h						Simple special purpose "standard" string class.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
//
//	Helper class to make an object out of a string-pointer, thereby
//	enabling proper deletion, regardless of how a function is exited.
//
class CStrPtr {
	LPTSTR m_szStr;
public:
	// A collection of constructors.
	CStrPtr();
	CStrPtr(int iSiz);
	CStrPtr(CStrPtr& utStr);
	CStrPtr(LPCTSTR szStr);

	~CStrPtr();									// Delete allocated memory if any.
	operator LPTSTR();							// Return a buffer pointer, use with care.
	operator LPCTSTR();
	operator BYTE *();
	CStrPtr& operator= (LPCTSTR szStr);			// Proper copy-assignment
	CStrPtr& operator= (CStrPtr& utStr);		// Proper copy-assignment
	CStrPtr& operator+ (CStrPtr& utStr);		// Ok - so we had to do this too. Sigh.
	LPTSTR Ptr();								// Return and dissociate the pointer.
};
#endif	_CSTRPTR