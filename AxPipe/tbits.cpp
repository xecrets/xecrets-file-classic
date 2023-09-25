/*! \file
	\brief Implementation of AxPipe::Stock::TBits

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2023 Svante Seleborg/Axon Data, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:axpipe@axondata.se and http://axpipe.sourceforge.net

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-15              Initial
\endverbatim
*/
#include "stdafx.h"
#include "TBits.h"

// Can't use this for convenient notation below:
// using AxPipe::Stock::TBits;
// because the Doxygen get's confused.

namespace AxPipe {
	namespace Stock {
		// Instantiate explicitly to generate code for supported bit-lengths.
		template TBits<128>;                ///< 128-bit instantiation of bit-block
		template TBits<160>;                ///< 160-bit instantiation of bit-block
		template TBits<256>;                ///< 256-bit instantiation of bit-block

		/// Zero-initialize
		/// the Bit buffer
		template<int iBits> TBits<iBits>::TBits() {
			ZeroMemory(m_Bits, sizeof m_Bits);
		}

		/// If shorter, pad on the right, i.e. with the Least
		/// Signifcant Bytes (sic!)
		/// \param bpInit Pointer to a sequence of bytes to initalize with
		/// \param cb Number of bytes in the init sequence (to use)
		template<int iBits> TBits<iBits>::TBits(unsigned char* bpInit, int cb) {
			ZeroMemory(m_Bits, sizeof m_Bits);
			CopyMemory(m_Bits, bpInit, cb < sizeof m_Bits ? cb : sizeof m_Bits);
		}

		/// Get the left-most n bits. This is actually sort of a dummy function,
		/// as we return a pointer, and the left-most always start at the beginning
		/// of the byte buffer where the bits are.
		/// \param n The number of bits to get.
		/// \return A pointer to the left-most n bits of the buffer.
		template<int iBits> void*
			TBits<iBits>::GetLeft(const int n) {
			n; //Dummy for C4100
			return &m_Bits;
		}

		/// Get the right-most n bits. Assume that this is a multiple by 8 value,
		/// otherwise the function fails silently.
		/// \return A pointer to the right-most n bits of the buffer.
		template<int iBits> void*
			TBits<iBits>::GetRight(const int n) {
			return &m_Bits[sizeof m_Bits - n / 8];
		}

		/// Arbitrary precision add, endian independent, inefficient...
		/// Note that the byte arrays is presumed to be stored big-endian!
		/// \param rhs A TBits
		/// \return A reference to the destination result, as it should.
		template<int iBits> TBits<iBits>&
			TBits<iBits>::operator += (const TBits<iBits>& rhs) {
			bool bCarry = false;
			for (int i = sizeof m_Bits; i >= 0; i--) {
				bCarry = (m_Bits[i] += rhs.m_Bits[i] + (unsigned char)bCarry) < rhs.m_Bits[i];
			}
			return *this;
		}

		/// Arbitrary precision XOR, inefficient. Don't use if you're in a hurry.
		/// \param rhs A TBits
		/// \return A reference to the destination result, as it should.
		template<int iBits> TBits<iBits>&
			TBits<iBits>::operator ^=(const TBits<iBits>& rhs) {
			size_t cb = sizeof m_Bits;
			unsigned char* dst = m_Bits;
			const unsigned char* src = rhs.m_Bits;
			while (cb--) {
				*dst++ ^= *src++;
			}
			return *this;
		}

		/// Copy-Assign
		/// \param rhs A TBits
		/// \return A reference to the destination result, as it should.
		template<int iBits> TBits<iBits>&
			TBits<iBits>::operator =(const TBits<iBits>& rhs) {
			CopyMemory(&m_Bits, &rhs.m_Bits, sizeof m_Bits);
			return *this;
		}
	}
}