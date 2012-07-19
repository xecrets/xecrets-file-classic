#ifndef _TYPES
#define	_TYPES
/*
    @(#) $Id$

	Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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
	Types.h							Operations on basic encryption types (hashes, keys etc).

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include "../AxCryptCommon/DQWORD.h"

#pragma warning(disable:4786)           // debug info truncated to 255 chars
#include <algorithm>
#include <memory>
#include <string>

#include <vector>
#include <map>

using namespace std;

// Modify according to compiler version. Include appropriate #ifdef's.
typedef __int64 longlong;                   ///< Substitute for long long which is not always supported
typedef unsigned __int64 ulonglong;         ///< Substitute for unsigned long long which is not always supported

//
//	Define some useful types. These are not complete definitions, they only
//	implement operations that are actually used and needed.
//
//	The purpose is to make the code a little easier to read, and also to make it
//	easier to upgrade cipher and hash strengths.
//
//	Please remember to always code according to:
//	1 - Always pass pointers to these classes
//	2 - Always use the secure heap for anything remotely sensitive - i.e. all here...
//
//	Much, some or all of this should perhaps be done with templates instead...
//

//
//	The basic size of the hash used, currently SHA-1, 160-bit.
//	We practically always treat this as an array of bytes.
//

//
//	Algorithm key and block, 128 bits
//
typedef DQWORD TKey;
typedef DQWORD TBlock;
//
//	A hashed key - used in validation data encryption keys for example.
//
typedef DQWORD TKeyHash;
//
//	File MAC, HMAC-SHA1-128
//
class THash;								// Forward
class THmac : public DQWORD {
public:
	THmac& operator =(THash& utH);			// Assignment of a Hash to a HMAC.
};
//
//	SHA-1, i.e. 160 bits
//
class THash {
private:
	BYTE aoH[20];
public:
	THash();								// Zero-initialized
	THash(BYTE *bpInit, int i);				// Byte-string initialized
	THash(QWORD qwV);						// QWORD initialized
	THmac* Hmac();							// Get HMAC (subset) of hash
	TKey* KeyHash();						// Get Key (subset) of hash
	THash& operator+(THash& rutHash);		// Do long addition of two hashes.
};
//
//	Arbitrary precision add, endian independent, inefficient...
//	Note that byte arrays in these contexts are presumed stored big-endian!
//
inline void
VLongAdd(BYTE *opSum, BYTE *opTerm, int iLen) {
	BYTE oCarry = 0;
	for (int i = iLen-1; i >= 0; i--) {
		oCarry = (opSum[i] += opTerm[i] + oCarry) < opTerm[i];
	}
}
#endif	_TYPES