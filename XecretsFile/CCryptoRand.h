#ifndef	_CCRYPTORAND
#define	_CCRYPTORAND
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
	CCryptoRand.cpp					Entropy pool and random number generator (FIPS 186-2).

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include	"CSha1.h"
//
//	CCryptoRand.h - Pseudo Random Number Generator using FIPS 186-2 with SHA-1.
//		Reference:  http://csrc.nist.gov/publications/fips/fips186-2/fips186-2.pdf
//
//	Svante Seleborg
//
//	2001-10-07	Initial
//
class CCryptoRand {
public:
	CCryptoRand();
	~CCryptoRand();
	CCryptoRand& Seed(void* pvXSeed, int iLen);
	void RandomFill(void* vpBuf, DWORD dwLen);
private:
	BYTE m_aoEntropyPool[128];
	unsigned int uiPoolIndex;
	THash* m_putXKey;		// The next XKEY to use.
	THash* m_putXSeed;		// The next XSEED to use.
	static DWORD m_dwInitKey[5];	// Initial XKEY used.
	SHA1_CTX* m_putContext;
};
#endif _CCRYPTORAND