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
	Types.cpp						Operations on basic encryption types (hashes, keys etc).

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
//
//	This is not a complete implementation of respective types, bud ad-hoc of what
//	was needed to make the main code readable and easy to modify if the underlying
//	algorithms or for example key lengths are modified.
//
#include	"StdAfx.h"
//
// Default initialization - zero.
//
THash::THash() {
	ZeroMemory(aoH, sizeof aoH);
}
//
//	Initialize with arbitrary byte string, from left to right.
//	If shorter, pad on the right, i.e. with the Least
//	Signifcant Bytes (sic!)
//
THash::THash(BYTE* bpInit, int i) {
	ZeroMemory(aoH, sizeof aoH);
	CopyMemory(aoH, bpInit, i < sizeof aoH ? i : sizeof aoH);
}
//
//	Initialize with an integer, QWORD is the largest native so it will have
//	to do.
//
THash::THash(QWORD qwV) {
	int i = sizeof THash - 1;
	while (qwV) {
		aoH[i] = (BYTE)qwV;
		qwV >>= 8;
		i--;
	}
}
//
//	Return a (subset) useful as the HMAC.
//	It says 'leftmost' bits in the RFC...
//
THmac*
THash::Hmac() {
	return (THmac*)&aoH[0];
}
//
//	Return a (subset) useful as an encryption Key.
//	To be consistent we return the most signifant bytes.
//
TKey*
THash::KeyHash() {
	return (TKey*)&aoH[0];
}
//
//	Perform arbitrary, endianess independent long addition.
//	This is not a common operation, so we need not be particularily
//	optimized here.
//
//	We treat the number as being stored big-endian.
//
THash&
THash::operator+(THash& utHash) {
	VLongAdd(aoH, utHash.aoH, sizeof utHash);
	return *this;
}
//
//	Assigment from a Hash to a HMAC.
//
THmac&
THmac::operator =(THash& utH) {
	CopyMemory(this, &utH, sizeof * this);
	return *this;
}