#ifndef	_DQWORD
#define	_DQWORD
/*
    @(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	DQWORD.h						Basic 128-bit operations

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/

#ifndef QWORD
#define QWORD unsigned __int64
#endif

//
//	DQWORD - Basic 128 bit operations as needed here.
//
class DQWORD {
	QWORD m_dqwBits[2];
public:
	DQWORD() {
		m_dqwBits[0] = m_dqwBits[1] = 0;
	}

	DQWORD(int i) {
		m_dqwBits[0] = i;
		m_dqwBits[1] = i < 0 ? 0xffffffffffffffff : 0;
	}

	DQWORD(DQWORD& dqwBits) {
		m_dqwBits[0] = dqwBits.m_dqwBits[0];
		m_dqwBits[1] = dqwBits.m_dqwBits[1];
	}

	DQWORD& operator= (QWORD *pdqwBits) {
		m_dqwBits[0] = pdqwBits[0];
		m_dqwBits[1] = pdqwBits[1];
		return *this;
	}
	DQWORD& operator= (DQWORD& dqwBits) {
		m_dqwBits[0] = dqwBits.m_dqwBits[0];
		m_dqwBits[1] = dqwBits.m_dqwBits[1];
		return *this;
	}
	DQWORD& operator= (int i) {
		m_dqwBits[0] = i;
		m_dqwBits[1] = i < 0 ? 0xffffffffffffffff : 0;
		return *this;
	}
	DQWORD& operator^= (DQWORD& dqwBits) {
		m_dqwBits[0] ^= dqwBits.m_dqwBits[0];
		m_dqwBits[1] ^= dqwBits.m_dqwBits[1];
		return *this;
	}
	DQWORD operator^ (DQWORD& dqwBits) {
		DQWORD dqwResult;
		dqwResult.m_dqwBits[0] = m_dqwBits[0] ^ dqwBits.m_dqwBits[0];
		dqwResult.m_dqwBits[1] = m_dqwBits[1] ^ dqwBits.m_dqwBits[1];
		return dqwResult;
	}

	int operator== (DQWORD& dqwBits) {
		return (m_dqwBits[0] == dqwBits.m_dqwBits[0]) && (m_dqwBits[1] == dqwBits.m_dqwBits[1]);
	}
	DQWORD& operator~() {
		m_dqwBits[0] = ~m_dqwBits[0];
		m_dqwBits[1] = ~m_dqwBits[1];
		return *this;
	}
    QWORD& Msb64() {
        return m_dqwBits[0];
    }
    QWORD& Lsb64() {
        return m_dqwBits[1];
    }
	/*
	DQWORD& Export(QWORD *pdqwBits) {
		pdqwBits[0] = m_dqwBits[0];
		pdqwBits[1] = m_dqwBits[1];
		return *this;
	}
	DQWORD& Export(void *pvBits) {
		return Export((QWORD *)pvBits);
	}*/
};
#endif _DQWORD