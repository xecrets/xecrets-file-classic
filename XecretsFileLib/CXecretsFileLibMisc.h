#ifndef CXECRETSFILELIBMISC_H
#define CXECRETSFILELIBMISC_H
/*! \file
	\brief CXecretsFileLibMisc.h - Miscellaneous definitions for CXecretsFileLib

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
extern "C" {
#include "XecretsFileLib.h"
}
#include "../AxPipe/AxPipe.h"
#include "XecretsFileLibPP.h"
#include "../AxPipe/CFileIO.h"

#include "Assert.h"
#define ASSERT_FILE "CXecretsFileLibMisc.h"

namespace axcl {
#ifdef _DEBUG
	const int chunkSize = 0x101;              ///< The chunk size we work in.
#else
	const int chunkSize = 0x100000;           ///< The chunk size we work in.
#endif

/// \brief The Xecrets File GUID
	extern byte guidAxCryptFileIdInverse[16];

	/// \brief Custom error codes from ::AxPipe -derived classes.
	enum {
		ERROR_CODE_XECRETSFILE = AxPipe::ERROR_CODE_DERIVED, ///< Generic custom error
		ERROR_CODE_CANCEL,                      ///< User cancelled in a dialog box before start
		ERROR_CODE_HMAC,                        ///< HMAC does not match
		ERROR_CODE_ABORT,                       ///< User cancelled whilst working
		ERROR_CODE_MORE,                        ///< Not an error - want a bigger dialog
		ERROR_CODE_WRONGKEY,                    ///< The key provided does not work for this data
		XECRETSFILE_CODE_DATA,                      ///< Not an error - we found Xecrets File Classic data status
	};

	/// \brief Simple helper to XOR two memory blocks to a third.
	/// \param dst The destination (can be the same as any of the sources)
	/// \param src1 The first of the sources to XOR
	/// \param src2 The second of the sources to XOR
	/// \param nBytes The number of bytes to XOR
	inline void
		XorMemory(void* dst, const void* src1, const void* src2, size_t nBytes) {
		while (nBytes--) *((unsigned char*&)(dst))++ = *((const unsigned char*&)src1)++ ^ *((const unsigned char*&)src2)++;
	}

	/// \brief A source for decryption, also reporting progress
	/// This class
	class CSourceProgressCancel : public AxPipe::CSourceFileIO {
		typedef AxPipe::CSourceFileIO base;

	private:
		axcl::longlong m_cb;                    ///< The number of bytes processed
		AXCL_PARAM* m_pParam;                   ///< All the collective controlling stuff

	public:
		/// \brief Initialize member variables
		CSourceProgressCancel() {
			m_cb = 0;
			m_pParam = NULL;
		}

		CSourceProgressCancel* Init(AXCL_PARAM* pParam, const _TCHAR* szPathName, size_t cbChunkSize) {
			base::Init(szPathName, cbChunkSize);
			m_pParam = pParam;
			return this;
		}

		/// \brief Check the provided bool location for cancel
		///
		/// If cancel is indicated, drop the segment and set an error
		/// code, ERROR_CODE_ABORT
		/// \param pSeg A segment we just pass on after checking for cancel
		void Out(AxPipe::CSeg* pSeg) {
			ASSPTR(m_pParam);
			m_cb += pSeg->Len();
			// Be careful to scale downwards here and avoid division by zero
			axcl::int64 i64ScaledDivisor = FileSize() / 100;
			m_pParam->iProgress = i64ScaledDivisor == 0 ? 100 : static_cast<int>(m_cb / i64ScaledDivisor);
			// Handle rounding errors due to truncation in the divisor above
			if (m_pParam->iProgress > 100) {
				m_pParam->iProgress = 100;
			}
			int iReturn = AXCL_E_INTERNAL;
			m_pParam->pfCallback(m_pParam, AXCL_A_PROGRESS, NULL, 0, &iReturn);

			if (iReturn == AXCL_E_OK) {
				Pump(pSeg);
			}
			else {
				pSeg->Release();
				if (iReturn == AXCL_E_CANCEL) {
					SetError(axcl::ERROR_CODE_ABORT, _T("Processing aborted"));
				}
				else {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Unexpected error in AXCL_A_PROGRESS"));
				}
			}
		}

		/// \brief Do the whole thing and return the status code and text
		///
		/// If anything but AXCL_E_OK is returned, the parameter-block string
		/// member AXCL_STR_ERRORMSG is set to a clear-text representation of the
		/// error in English.
		/// \return A status code, AXCL_E_OK if all ok, otherwise an error code.
		int FullProcess() {
			// Run the input through the pipe...
			int iErrorCode = Open()->Drain()->Close()->Plug()->GetErrorCode();
			// ...and return with a AxPipe::-style error code, i.e. ERROR_CODE_XXXX

			int iAxclCode;
			_TCHAR* pErrorMsg;
			switch (iErrorCode) {
			case AxPipe::ERROR_CODE_SUCCESS:
			case AxPipe::ERROR_CODE_STOP:
				return AXCL_E_OK;
				// Processing was aborted after having started
			case axcl::ERROR_CODE_ABORT:
				// fall through...
				// Processing was never started, the user cancelled before then
			case axcl::ERROR_CODE_CANCEL:
				iAxclCode = AXCL_E_CANCEL;
				pErrorMsg = _TT("User Cancelled");
				break;
			case axcl::ERROR_CODE_WRONGKEY:
				iAxclCode = AXCL_E_WRONGKEY;
				pErrorMsg = GetErrorMsg();
				break;
			default:
				iAxclCode = AXCL_E_XECRETSFILE;
				pErrorMsg = GetErrorMsg();
				break;
			}

			if (iAxclCode != AXCL_E_OK) {
				// Ensure we have room in the destination buffer.
				delete[] m_pParam->strBufs[AXCL_STR_ERRORMSG];
				m_pParam->strBufs[AXCL_STR_ERRORMSG] = new _TCHAR[axcl::tstrlen(pErrorMsg) + 1];
				axcl::tstrcpy(m_pParam->strBufs[AXCL_STR_ERRORMSG], pErrorMsg);
			}

			return m_pParam->iResultCode = iAxclCode;
		}
	};
}

#endif CXECRETSFILELIBMISC_H