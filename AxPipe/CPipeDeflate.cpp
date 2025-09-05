/*! \file
	\brief Implementation of AxPipe::Stock::CPipeDeflate

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2005-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	axpipe@axantum.com              2005-11-04              Initial
\endverbatim
*/
#include "stdafx.h"
#include "CPipeDeflate.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipeDeflate.cpp"

// Can't use this for convenient notation below:
// using AxPipe::Stock::CPipeInflate;
// because the Doxygen get's confused.

namespace AxPipe {
	namespace Stock {
		static voidpf zalloc OF((voidpf opaque, uInt items, uInt size)) {
			// The semantics of zalloc are a bit unclear, so we always zero the memory...
			return memset(new unsigned char[items * size], 0, items * size);
		}

		static void zfree OF((voidpf opaque, voidpf address)) {
			delete[] static_cast<unsigned char*>(address);
		}

		/// \brief Initialize member variables
		CPipeDeflate::CPipeDeflate() {
			m_cbChunkSize = 0;
			m_cbFlushInterval = 0;
			m_pOutSeg = NULL;
			m_cbIn = 0;
			m_cbOut = 0;
			m_cbLastTotal_in = m_cbLastTotal_out = 0;
			ZeroMemory(&m_Zstream, sizeof m_Zstream);
		}

		///< \brief Initialize the flush interval
		/// \param cbChunkSize The size we output in. Collect this much before outputting.
		/// \param cbFlushInterval The frequence with which we make resync possible at decompression time. 0 means never.
		CPipeDeflate* CPipeDeflate::Init(int nSaveRatioForCompress, size_t cbChunkSize, size_t cbFlushInterval) {
			m_nSaveRatioForCompress = nSaveRatioForCompress;
			m_cbChunkSize = cbChunkSize;
			m_cbFlushInterval = cbFlushInterval;
			return this;
		}

		/// Clean up if necessary, should only need
		/// work to be done on error.
		CPipeDeflate::~CPipeDeflate() {
			if (m_pOutSeg) {
				m_pOutSeg->Release();
			}
		}

		/// Private helper to send the current segment onwards. m_pOutSeg is
		/// always NULL at return.
		void
			CPipeDeflate::SendOut() {
			if (m_pOutSeg) {
				// Update statistics
				m_cbOut += m_Zstream.total_out - m_cbLastTotal_out;
				m_cbLastTotal_out = m_Zstream.total_out;

				m_pOutSeg->Len(m_pOutSeg->Len() - m_Zstream.avail_out);
				Pump(m_pOutSeg);
				m_pOutSeg = NULL;
			}
		}

		/// Allocate a new segment to deflate to, and update the z_stream structure accordingly
		void
			CPipeDeflate::AllocNew() {
			// Get a new segment, either of the chunk size, or the available in plus 6 (see zlib docs)
			m_pOutSeg = new AxPipe::CSeg(m_cbChunkSize ? m_cbChunkSize : (m_Zstream.avail_in / 2 + 6));
			ASSPTR(m_pOutSeg);

			m_Zstream.next_out = m_pOutSeg->PtrWr();
			m_Zstream.avail_out = static_cast<UINT>(m_pOutSeg->Size());
		}

		/// Initialize the z_stream structure, including memory allocation functions
		/// \param pZstream Pointer to a z_stream structure
		void
			CPipeDeflate::InitZstream(z_stream* pZstream) {
			memset(pZstream, 0, sizeof * pZstream);
			pZstream->zalloc = zalloc;      // Use our custom alloc()
			pZstream->zfree = zfree;        // Use our custom free()

			if (deflateInit(pZstream, Z_DEFAULT_COMPRESSION) != Z_OK) {
				SetError(ERROR_CODE_STOCK, _T("ZLIB initialization error"));
			}
		}

		longlong CPipeDeflate::GetOutputSize() {
			return m_cbOut;
		}

		longlong CPipeDeflate::GetInputSize() {
			return m_cbIn;
		}

		int CPipeDeflate::TryDeflateLoop(AxPipe::CSeg* pSeg, z_stream* pZstream) {
			int iZerror;
			do {
				// We now have updated available input, so we call deflate and check the result...
				iZerror = deflate(pZstream, Z_FINISH);
				switch (iZerror) {
				case Z_OK:
					// re-use the buffer - we're not really interested in the data as such
					pZstream->next_out = const_cast<unsigned char*>(pSeg->PtrRd());
					pZstream->avail_out = static_cast<uInt>(pSeg->Len());
					break;
				case Z_STREAM_END:
					break;
				case Z_BUF_ERROR:
				case Z_STREAM_ERROR:
				default:
					SetError(ERROR_CODE_STOCK, _T("ZLIB sequence error in CPipeDeflate::TryDeflate()"));
					return iZerror;
				}
			} while (iZerror != Z_STREAM_END);
			return iZerror;
		}

		/// Try deflation of a memory buffer and return the resulting size
		/// \param p Pointer to data to try to deflate
		/// \param cb The number of bytes in the data buffer
		/// \return The total number of bytes necessary, including overhead
		size_t
			CPipeDeflate::TryDeflate(const void* p, size_t cb) {
			z_stream Zstream;
			InitZstream(&Zstream);

			// Allocate a reasonable buffer, at least 6 bytes large (to make room for header)
			AxPipe::CSeg* pSeg = new AxPipe::CSeg(cb / 2 + 6);
			Zstream.next_in = const_cast<unsigned char*>(static_cast<const unsigned char*>(p));
			Zstream.avail_in = static_cast<uInt>(cb);
			Zstream.next_out = const_cast<unsigned char*>(pSeg->PtrRd());
			Zstream.avail_out = static_cast<uInt>(pSeg->Len());

			int iZerror = TryDeflateLoop(pSeg, &Zstream);
			pSeg->Release();

			// Clean up memory allocations etc
			if (deflateEnd(&Zstream) != Z_OK) {
				SetError(ERROR_CODE_DERIVED, _T("ZLIB error in deflateEnd error"));
				return 0;
			}

			if (iZerror != Z_STREAM_END) {
				return 0;
			}
			return Zstream.total_out;
		}

		bool
			CPipeDeflate::IsDeflatable(AxPipe::CSeg* pSeg, int nSaveRatioForCompress) {
			size_t nDeflatedForPercent = TryDeflate(pSeg->PtrRd(), pSeg->Len());
			size_t nOriginalForPercent = pSeg->Len();
			if (nDeflatedForPercent < (~size_t(0)) / size_t(100)) {
				nDeflatedForPercent *= 100;
			}
			else {
				nOriginalForPercent /= 100;
				if (nOriginalForPercent == 0) {
					// Avoid division by zero
					nOriginalForPercent = 1;
				}
			}
			int nSaveRatio = 100 - static_cast<int>(nDeflatedForPercent / nOriginalForPercent);
			if (nSaveRatio < 0) {
				nSaveRatio = 0;
			}
			return nSaveRatio >= m_nSaveRatioForCompress;
		}

		bool
			CPipeDeflate::IsDeflating() {
			return m_fDeflate;
		}

		/// Initialize zlib for this deflation.
		/// \return true to continue cascading of Open()
		bool
			CPipeDeflate::OutOpen() {
			bool fReturn = CPipe::OutOpen();        // Open base first, like constructor
			m_cbOut = 0;                            // Total output bytes counter
			m_cbIn = 0;                             // Total input bytes counter
			m_cbRemainBeforeFlush = 0;
			m_fDeflate = true;                      // Default is to deflate
			InitZstream(&m_Zstream);                // Since we're assuming we're actually to deflate...
			AllocNew();
			ASSPTR(m_pOutSeg);

			return fReturn;                         // Return the saved return code.
		}

		/// Compress output as it arrives. We also produce Z_FULL_FLUSH periodically to
		/// ensure that there is a certain redundancy. We always consume all data that is
		/// input, but it may be sent onwards in multiple segments.
		/// \param pSeg A segment with compressed data, and no trailing if last
		void
			CPipeDeflate::Out(AxPipe::CSeg* pSeg) {
			// If we're asked to try before compression, test once
			if (m_nSaveRatioForCompress) {
				m_fDeflate = IsDeflatable(pSeg, m_nSaveRatioForCompress);
				m_nSaveRatioForCompress = 0;
			}

			// If we're not deflating, just pass the segment onwards.
			if (!m_fDeflate) {
				m_cbIn = m_cbOut += pSeg->Len();
				Pump(pSeg);
				return;
			}

			size_t cb = pSeg->Len();
			unsigned char* p = const_cast<unsigned char*>(pSeg->PtrRd());
			while (cb) {
				m_Zstream.next_in = p;
				size_t cbThisCall = cb;
				if (m_cbFlushInterval) {
					if (m_cbRemainBeforeFlush == 0) {
						m_cbRemainBeforeFlush = m_cbFlushInterval;
					}
					cbThisCall = cb > m_cbRemainBeforeFlush ? m_cbRemainBeforeFlush : cb;
					m_cbRemainBeforeFlush -= cbThisCall;
				}

				// The amount to consume is determined by how much is available, and the flush interval
				m_Zstream.avail_in = static_cast<uInt>(cbThisCall);
				p += cbThisCall;
				cb -= cbThisCall;

				while (m_Zstream.avail_in) {
					do {
						if (m_Zstream.avail_out == 0) {
							SendOut();
							AllocNew();
						}

						// We now have updated available input, so we call deflate and check the result...
						int iZerror = deflate(&m_Zstream, (m_cbFlushInterval && (m_cbRemainBeforeFlush == 0)) ? Z_FULL_FLUSH : 0);
						switch (iZerror) {
						case Z_OK:
							break;
						case Z_BUF_ERROR:
						case Z_STREAM_END:
						case Z_STREAM_ERROR:
						default:
							SetError(ERROR_CODE_STOCK, _T("ZLIB sequence error in CPipeDeflate::Out()"));
							pSeg->Release();
							return;
						}
					} while (m_Zstream.avail_out == 0);
					m_cbIn += m_Zstream.total_in - m_cbLastTotal_in;
					m_cbLastTotal_in = m_Zstream.total_in;
				}
			}
			pSeg->Release();
		}

		/// Flush all data and end the deflation run.
		/// \return true to cascade the closing of the stream
		bool
			CPipeDeflate::OutClose() {
			if (!GetErrorCode() && m_fDeflate) {
				int iZerror;
				do {
					iZerror = deflate(&m_Zstream, Z_FINISH);
					switch (iZerror) {
					case Z_OK:
						SendOut();
						AllocNew();
						break;
					case Z_STREAM_END:
						break;
					case Z_BUF_ERROR:
					case Z_STREAM_ERROR:
					default:
						SetError(ERROR_CODE_STOCK, _T("ZLIB sequence error in CPipeDeflate::OutClose()"));
						return false;
					}
				} while (iZerror != Z_STREAM_END);

				// Final output
				SendOut();
			}

			// Clean up memory allocations etc
			if (deflateEnd(&m_Zstream) != Z_OK) {
				SetError(ERROR_CODE_DERIVED, _T("ZLIB error in deflateEnd error"));
			}

			return base::OutClose();
		}
	}
}