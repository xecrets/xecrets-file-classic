#ifndef	_CSHA1
#define	_CSHA1
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
	CSha1.h							Special purpose wrapper for Steve Reids SHA-1 code.

	E-mail							YYYY-MM-DD				Reason
	axcrypt@axondata.se 			2001					Initial

*/
extern "C" {
#include "../SHA-1/sha1.h"
}

class CSha1 {
	SHA1_CTX *m_putContext;
public:
	CSha1();
	~CSha1();
	TKey *GetKeyHash(BYTE *poMsg, size_t iLen, TCHAR *szFileName = NULL);
};
#endif	_CSHA1
