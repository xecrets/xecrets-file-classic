#ifndef BLOCKTYPES_H
#define BLOCKTYPES_H
/*! \file
	\brief BlockTypes.h - Crypto-related block types

	@(#) $Id$

	axcl - Xecrets File Classic support classes and types

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
*/

#include "Assert.h"
#define ASSERT_FILE "BlockTypes.h"

namespace axcl {
	/// \brief Basic Block template. Please note! The size must be a multiple of sizeof uint32.
	template<int cbSize> class TLongBlock {
	protected:
		uint32 m_aTheBits[cbSize / sizeof(uint32)];
	public:
		TLongBlock(const void* bpInit = NULL, size_t cb = 0) {
			memset(m_aTheBits, 0, sizeof m_aTheBits);
			memcpy(m_aTheBits, bpInit, cb < sizeof m_aTheBits ? cb : sizeof m_aTheBits);
		}

		TLongBlock(int i) {
			// TODO: This is actually a bug - the value should be at the highest index (i.e. Lsb).
			// retained temporarily for compatibility with Xecrets File Classic version 1.x, since it initializes
			// subkeys using similar code to this. It's not a security problem - it's just silly.
			m_aTheBits[0] = i;
			for (size_t ix = 1; ix < sizeof m_aTheBits / sizeof * m_aTheBits; ix++) {
				m_aTheBits[ix] = i < 0 ? ~0L : 0L;
			}
		}

		/// \brief Perform arbitrary, endianess independent long addition.
		//  This is not a common operation, so we need not be particularily
		//  optimized here.
		//  Arbitrary precision add, endian independent, inefficient...
		//  Note that byte arrays in these contexts are presumed stored big-endian!
		TLongBlock& operator+(TLongBlock& rhs) {
			byte oCarry = 0;
			size_t ix = sizeof m_aTheBits - 1;
			do {
				oCarry = (((byte*)m_aTheBits)[ix] += ((byte*)rhs.m_aTheBits)[ix] + oCarry) < ((byte*)rhs.m_aTheBits)[ix] ? 1 : 0;
			} while (ix--);
			return *this;
		}

		TLongBlock& operator^= (TLongBlock& rhs) {
			for (size_t ix = 0; ix < sizeof m_aTheBits / sizeof * m_aTheBits; ix++) {
				m_aTheBits[ix] ^= rhs.m_aTheBits[ix];
			}
			return *this;
		}

		TLongBlock operator^ (TLongBlock& rhs) {
			TLongBlock result;
			for (size_t ix = 0; ix < sizeof m_aTheBits / sizeof * m_aTheBits; ix++) {
				result.m_aTheBits[ix] = m_aTheBits[ix] ^ rhs.m_aTheBits[ix];
			}
			return result;
		}

		int operator== (TLongBlock& rhs) {
			return memcmp(m_aTheBits, rhs.m_aTheBits, sizeof m_aTheBits) == 0;
		}

		TLongBlock& operator~() {
			for (size_t ix = 0; ix < sizeof m_aTheBits / sizeof * m_aTheBits; ix++) {
				m_aTheBits ^= ~0L;
			}
			return *this;
		}

		const unsigned char* get(int i = 0) {
			return &static_cast<const unsigned char*>(m_aTheBits)[i];
		}
	};

	class T128Bit : public TLongBlock<16> {
	public:
		T128Bit(byte* bpInit = NULL, size_t cb = 0) : TLongBlock<16>(bpInit, cb) {
		}

		T128Bit(int i) : TLongBlock<16>(i) {
		}

		uint64& Msb64() {
			return *(uint64*)&m_aTheBits[0];
		}

		uint64& Lsb64() {
			return *(uint64*)&m_aTheBits[2];
		}
	};

	typedef T128Bit TKey;
	typedef T128Bit THmac;
	typedef T128Bit TBlock;

	/// \brief Encapsulate a non-secret fingerprint - half the size of a key
	class TFingerprint : public TLongBlock<sizeof(TKey) / 2> {
	public:
		TFingerprint(unsigned char* pKey, size_t cbKey) {
			ASSCHK(cbKey >= (sizeof m_aTheBits * 2), _TT("Internal error, key too short for fingerprint algorithm"));
			memset(m_aTheBits, 0, sizeof m_aTheBits);
			for (unsigned int i = 0; i < cbKey; i++) {
				reinterpret_cast<byte*>(m_aTheBits)[i % sizeof m_aTheBits] ^= pKey[i];
			}
		}
	};

	class THash : public TLongBlock<20> {
	public:
		//  Return a (subset) useful as the HMAC.
		//  It says 'leftmost' bits in the RFC...
		THmac* Hmac() {
			return (THmac*)this;
		}

		TKey* KeyHash() {
			return (TKey*)this;
		}
	};
}
#endif BLOCKTYPES_H