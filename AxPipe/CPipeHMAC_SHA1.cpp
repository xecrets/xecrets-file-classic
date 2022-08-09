/*! \file
	\brief Implementation of AxPipe::Stock::TPipeHMAC_SHA1

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2022 Svante Seleborg/Axon Data, All rights reserved.

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
#include "CPipeHMAC_SHA1.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipeHMHAC_SHA1.cpp"

// Make for some more convenient notation below
// using AxPipe::Stock::CPipeHMAC_SHA1;
// using AxPipe::Stock::TBits;
namespace AxPipe {
	namespace Stock {
		// Instantiate explicitly to generate code for supported bit-lengths.
		template CPipeHMAC_SHA1<128>;       ///< 128-bit instantiation of HMAC_SHA1
		template CPipeHMAC_SHA1<160>;       ///< 160-bit instantiation of HMAC_SHA1

		/// Do the HMAC XOR operation, with the inner or outer pad.
		/// Basically its the value XOR the Key, but if the key is
		/// shorter, we simulate zero-extending it.
		///
		/// \param oPad The byte to XOR the Key with.
		template<int iBits> void
			CPipeHMAC_SHA1<iBits>::XorPad(unsigned char oPad) {
			for (int i = 0; i < sizeof m_HMAC; i++) {
				((unsigned char*)&m_HMAC)[i] = oPad;
				if (i < sizeof m_Key) {
					((unsigned char*)&m_HMAC)[i] ^= ((unsigned char*)&m_Key)[i];
				}
			}
		}

		/// Initialize the key and the offset.
		///
		/// \param pKey A TBits comprising the key of the HMAC operation.
		/// \param cbOffset The number of bytes to skip in the stream before beginning
		/// \return A pointer to 'this'
		template<int iBits> CPipeHMAC_SHA1<iBits>*
			CPipeHMAC_SHA1<iBits>::Init(TBits<iBits>* pKey, size_t cbOffset) {
			CopyMemory(&m_Key, pKey, sizeof m_Key);
			m_cbOffset = cbOffset;          // Number of bytes to skip before starting to HMAC
			return this;
		}

		/// Hash the data into the HMAC, skipping if necessary. All data is
		/// passed unchanged, although segment boundaries may change.
		///
		/// \param pSeg The segment to hash, unless we're still skipping
		template<int iBits> void
			CPipeHMAC_SHA1<iBits>::Out(AxPipe::CSeg* pSeg) {
			if (pSeg->Len() <= m_cbOffset) {
				m_cbOffset -= pSeg->Len();
				Pump(pSeg);
			}
			else {
				if (m_cbOffset) {
					CSeg* pPartialSeg = pSeg->Clone();
					pPartialSeg->Len(m_cbOffset);
					Pump(pPartialSeg);

					pSeg->Drop(m_cbOffset);
					m_cbOffset = 0;
				}
				CPipeSHA1::Out(pSeg);
			}
		}

		/// Do the inner hash of the padded and XOR'ed key
		///
		/// \return true if the Open() call should be cascaded.
		template<int iBits> bool
			CPipeHMAC_SHA1<iBits>::OutOpen() {
			bool fReturn = CPipeSHA1::OutOpen();

			// K xor ipad
			XorPad(0x36);

			// Hash(iPad xor Key)
			ASSAPI(CryptHashData(m_hHash, (unsigned char*)&m_HMAC, sizeof m_HMAC, 0));

			return fReturn;
		}

		/// Do the outer hash of the padded and XOR'ed key, and also finalize
		/// the HMAC in the form of a hash. You get the hash by calling GetHash(),
		/// and the number of bytes processed with CountBytes().
		/// \return true if the Open() call should be cascaded.
		template<int iBits> bool
			CPipeHMAC_SHA1<iBits>::OutClose() {
			// Save the inner hash
			TBits<160> innerHash;
			DWORD dwHashLen = sizeof innerHash;
			ASSAPI(CryptGetHashParam(m_hHash, HP_HASHVAL, (unsigned char*)&innerHash, &dwHashLen, 0));

			// Re-initialize our hash-object.
			CryptDestroyHash(m_hHash);
			ASSAPI(CryptCreateHash(m_hCryptProv, CALG_SHA1, 0, 0, &m_hHash));

			// K xor opad
			XorPad(0x5c);

			// Hash(oPad xor Key)
			ASSAPI(CryptHashData(m_hHash, (unsigned char*)&m_HMAC, sizeof m_HMAC, 0));

			// Hash(InnerHash)
			ASSAPI(CryptHashData(m_hHash, (unsigned char*)&innerHash, sizeof innerHash, 0));

			// Prepare the final hash as output.
			return CPipeSHA1::OutClose();
		}
	}
}