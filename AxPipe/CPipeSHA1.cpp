/*! \file
	\brief Implementation of AxStock::CPipeSHA1, calculate SHA1 of the stream

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
#include "CPipeSHA1.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipeSHA1.cpp"

namespace AxPipe {
	namespace Stock {
		/// Acquire a Crypto Context to use
		///
		CPipeSHA1::CPipeSHA1() {
			if (!CryptAcquireContext(&m_hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) {
				SetError(AxPipe::ERROR_CODE_STOCK, _T("CPipeSHA1::CPipeSHA1() [CryptAcquireContext() failed: %s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
			}
			m_hHash = NULL;
		}

		/// Destroy the hash, if any and release the Crypto Context, if any.
		///
		CPipeSHA1::~CPipeSHA1() {
			if (m_hHash) CryptDestroyHash(m_hHash);
			if (m_hCryptProv) CryptReleaseContext(m_hCryptProv, 0);
		}

		/// Add the contents of the segment to the hash, count the bytes,
		/// and send the data onwards, unchanged.
		/// \param pSeg The segment to hash.
		void
			CPipeSHA1::Out(AxPipe::CSeg* pSeg) {
			if (!CryptHashData(m_hHash, pSeg->PtrRd(), (DWORD)pSeg->Len(), 0)) {
				SetError(AxPipe::ERROR_CODE_STOCK, _T("CPipeSHA1::CPipeSHA1() [CryptHashData() failed: %s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
			}
			m_cb += pSeg->Len();
			Pump(pSeg);
		}

		///
		/// \return The number of bytes hashed.
		unsigned __int64
			CPipeSHA1::CountBytes() {
			return m_cb;
		}

		///
		/// \return A pointer to the resulting hash, always 160 bits/20 bytes for SHA1.
		unsigned char*
			CPipeSHA1::GetHash() {
			return (unsigned char*)m_Hash.GetLeft(160);
		}

		/// Create the hash.
		/// \return true, if we see no reason not to propagate the Open() call
		bool
			CPipeSHA1::OutOpen() {
			bool fReturn = CPipe::OutOpen();

			if (!CryptCreateHash(m_hCryptProv, CALG_SHA1, 0, 0, &m_hHash)) {
				SetError(AxPipe::ERROR_CODE_STOCK, _T("CPipeSHA1::CPipeSHA1() [CryptCreateHash() failed: %s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
			}
			m_cb = 0;
			return fReturn;
		}

		/// Finalize and get the hash data into the buffer, and destroy the hash context.
		/// \return true if the Close() call should be propagated.
		bool
			CPipeSHA1::OutClose() {
			DWORD dwHashLen = sizeof m_Hash;
			if (!CryptGetHashParam(m_hHash, HP_HASHVAL, (unsigned char*)&m_Hash, &dwHashLen, 0)) {
				SetError(AxPipe::ERROR_CODE_STOCK, _T("CPipeSHA1::OutClose() [CryptGetHashParam() failed: %s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
			}
			ASSAPI(CryptDestroyHash(m_hHash) == TRUE);
			m_hHash = NULL;
			return CPipe::OutClose();
		}
	}
}