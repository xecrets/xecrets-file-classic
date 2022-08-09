#ifndef	_CFILETEMP
#define	_CFILETEMP
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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

	The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
	CFileTemp.h						Temp file related operations

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2001-12-01				Added CTempDir

*/
#include	"../XecretsFileCommon/CFileName.h"
//
//	Create temporary file
//
class CFileTemp : public CFileName {
public:
	CFileTemp() : CFileName() {}
	CFileTemp& New();
};
//
//	Create and destroy temporary directory.
//
class CTempDir : public CFileName {
public:

	CTempDir(DWORD nWipePasses) : CFileName() {
		m_nWipePasses = nWipePasses;
	}
	~CTempDir();

	CTempDir& New();				// Make a new temp-file.
	LPCTSTR Get();
	CTempDir& SetPath2TempDir();
private:
	DWORD RemoveDir();			    // Empty a directory and delete it.
	DWORD RmDir(LPCTSTR szDir);		// Helper to recursively delete a directory.
	DWORD m_nWipePasses;                    ///< The number of passes to wipe the temps
};
#endif	_CFILETEMP