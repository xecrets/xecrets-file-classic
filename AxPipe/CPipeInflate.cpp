/*! \file
	\brief Implementation of AxPipe::Stock::CPipeInflate

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
#include "CPipeInflate.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipeInflate.cpp"

// Can't use this for convenient notation below:
// using AxPipe::Stock::CPipeInflate;
// because the Doxygen get's confused.

namespace AxPipe {
	namespace Stock {
		static voidpf zalloc OF((voidpf opaque, uInt items, uInt size)) {
			opaque; //Dummy for C4100
			// The semantics of zalloc are a bit unclear, so we always zero the memory...
			return memset(new unsigned char[items * size], 0, items * size);
		}

		static void zfree OF((voidpf opaque, voidpf address)) {
			opaque; //Dummy for C4100
			delete[] static_cast<unsigned char*>(address);
		}

		/// \brief Initialize member variables
		CPipeInflate::CPipeInflate() {
			m_pOutSeg = NULL;
			m_cb = 0;
			m_cbLastTotal_in = m_cbLastTotal_out = 0;
			ZeroMemory(&m_Zstream, sizeof m_Zstream);
		}

		/// Clean up if necessary, should only need
		/// work to be done on error.
		CPipeInflate::~CPipeInflate() {
			if (m_pOutSeg) {
				m_pOutSeg->Release();
			}
		}

		/// Initialize zlib for this inflation.
		/// \return true to continue cascading of Open()
		bool
			CPipeInflate::OutOpen() {
			bool fReturn = CPipe::OutOpen();        // Open base first, like constructor
			m_cb = 0;                               // Total output bytes counter
			ZeroMemory(&m_Zstream, sizeof m_Zstream);
			m_Zstream.next_in = Z_NULL;	            // Defer check to first call to inflate
			m_Zstream.zalloc = zalloc;              // Use our custom alloc()
			m_Zstream.zfree = zfree;                // Use our custom free()

			if (inflateInit(&m_Zstream) != Z_OK) {
				SetError(ERROR_CODE_STOCK, _T("ZLIB initialization error"));
			}
			ASSCHK(m_pOutSeg == NULL, _T("CPipeInflate::OutOpen() [m_pOutSeg non-NULL]"));

			return fReturn;                         // Return the saved return code.
		}

		/// Clean up and call base class CPipe::OutClose()
		/// \return true to continue cascading the Open()
		bool
			CPipeInflate::OutClose() {
			// This is a safety first measure, should not really be needed.
			if (m_pOutSeg) {
				m_pOutSeg->Release();
				m_pOutSeg = NULL;
			}

			// Clean up memory allocations etc
			if (inflateEnd(&m_Zstream) != Z_OK) {
				SetError(ERROR_CODE_DERIVED, _T("ZLIB error in inflateEnd error"));
				return false;
			}

			return CPipe::OutClose();               // End by closing base, like destructor
		}

		/// Accept each segment as it is passed. It's important that you do not
		/// send more data than needed. The compression format is self-terminating,
		/// and there must be no data sent after the last byte of the compressed
		/// stream. If so, an error is set and that data is discarded. The output
		/// is decompressed, but may be sent in multiple segments.
		/// \param pSeg A segment with compressed data, and no trailing if last
		void
			CPipeInflate::Out(AxPipe::CSeg* pSeg) {
			m_Zstream.next_in = (unsigned char*)pSeg->PtrRd();
			m_Zstream.avail_in = (UINT)pSeg->Len();
			for (;;) {
				if (!m_pOutSeg) {
					// Allocate the output segment, and point the Zstream structure to it
					m_pOutSeg = GetSeg(m_Zstream.avail_in + m_Zstream.avail_in);
					ASSPTR(m_pOutSeg);
					m_Zstream.avail_out = (UINT)m_pOutSeg->Size();
					m_Zstream.next_out = m_pOutSeg->PtrWr();
				}
				int iZerror = inflate(&m_Zstream, 0);
				m_cb += m_Zstream.total_out - m_cbLastTotal_out; // Update total output bytes ctr
				m_Zstream.total_out = m_Zstream.total_out; // can't use total_out since it's 32-bit
				switch (iZerror) {
				case Z_OK:
					// ZLib guarantees to either use all input or all output buffer.
					if (m_Zstream.avail_in && m_Zstream.avail_out) {
						SetError(ERROR_CODE_DERIVED, _T("ZLIB sequence error"));
					}
					if (!m_Zstream.avail_out) {
						Pump(m_pOutSeg);
						m_pOutSeg = NULL;
					}
					if (m_Zstream.avail_in) {
						continue;                   // More data to inflate!
					}
					// If we have no more input, we need to return and wait for more
					break;
				case Z_STREAM_END:
					m_pOutSeg->Len(m_pOutSeg->Size() - m_Zstream.avail_out);
					Pump(m_pOutSeg);
					m_pOutSeg = NULL;
					if (m_Zstream.avail_in) {
						SetError(ERROR_CODE_STOCK, _T("Trailing data"));
					}
					break;
				default:
					SetError(ERROR_CODE_STOCK, _T("ZLIB inflate error"));
					break;
				}
				break;
			}
			pSeg->Release();
		}
	}
}