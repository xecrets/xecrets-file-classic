#ifndef	_CWRAPPER
#define	_CWRAPPER
/*
    @(#) $Id$

	AxCrypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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

	The author may be reached at mailto:axcrypt@axondata.se and http://axcrypt.sourceforge.net
----
	CWrapper.h						Batch the component operations of wrapping/unwrapping in one little class.

	E-mail							YYYY-MM-DD				Reason
	axcrypt@axondata.se 			2001					Initial
                                    2002-08-02              Ver 1.2

*/
#include	"CCryptoKey.h"
#include	"CFile.h"
#include	"../AxCryptCommon/CFileName.h"

//
//	Utility base class with various useful routines for
//	wrapping, unwrapping, and unwrap-launch-wrap etc.
//
class CWrapper {
    HWND m_hProgressWnd;
    bool m_fEnableProgress;

protected:
	CHeaders *m_pHeaders;

public:
	CWrapper(CHeaders *pHeaders, HWND hProgressWnd);
	void Wrap(CFileIO& rFilePlain, CFileIO& rFileCipher, DWORD nWipePasses, BOOL fSlowSafe = TRUE, BOOL fEnableProgress = TRUE);
	void Unwrap(CFileIO& rFileCipher, CFileIO& rFilePlain, DWORD nWipePasses, BOOL fSlowSafe = TRUE, BOOL fEnableProgress = TRUE);

private:
	// Parts of the job - separated just to make it clear.
	void CompressData(CFileIO& rFilePlain, CFileIO& rFileTmp);
	void EncryptData(CFileIO& rFilePlain, CFileIO& rFileCipher);

	void DecryptData(CFileIO& rFileCipher, CFileIO& rFilePlain);
	void DeCompressData(CFileIO& rFileTmp, CFileIO& rFilePlain);
};
#endif	_CWRAPPER
