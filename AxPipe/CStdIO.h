#ifndef CSTDIO_H
#define CSTDIO_H
/*! \file CStdIO.h
	\brief Standard Input and Output Source and Sink, AxPipe::CSourceStdIn and AxPipe::CSinkStdOut

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003 Svante Seleborg/Axon Data, All rights reserved.

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
	CStdIO.h                        Standard Input and Output Source and Sink

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2004-09-12              Initial
\endverbatim

	AxPipe Standard Input and Output source and sink classes.

	C[T]SourceStdIn  - a source [in it's own thread]
	C[T]SinkStdOut   - a sink [in it's own thread]

	Copyright 2003, Axon Data/Svante Seleborg, All Rights Reserved.
*/
#include    "AxPipe.h"
#include    <stdio.h>
#include    <stdlib.h>

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CStdIO.h"

namespace AxPipe {
	/// \brief A CSource providing data from standard input
	class CSourceStdIn : public CSource {
		size_t m_cbChunk;                       // The reading chunk-size
	public:
		/// \brief Set chunk size
		/// \param fBinary set to true for binary style reading
		/// \param cbChunk the size of the read buffer
		/// \return A pointer to this
		CSourceStdIn *Init(bool fBinary = false, size_t cbChunk = 64 * 1024) {
			m_cbChunk = cbChunk;
			ASSCHK(_setmode(_fileno(stdin), fBinary ? O_BINARY : O_TEXT) != -1, _T("CSourceStdIn::Init() setmode() failed"));
			return this;
		}

		/// \brief Set chunk size to default and stream-mode
		/// \param fBinary set to true binary style access
		CSourceStdIn(bool fBinary = false) {
			Init(fBinary);
		}

	protected:
		///< Get the next chunk from the input file
		/// \return data, or zero-length on EOF or NULL on error
		CSeg *In() {
			if (ferror(stdin)) {
				return NULL;
			}
			if (feof(stdin)) {
				return new CSeg(0);
			}
			CSeg *pSeg = new CSeg(m_cbChunk);
			size_t cbLen = fread(pSeg->PtrWr(), 1, pSeg->Size(), stdin);
			if (cbLen < pSeg->Size()) {
				if (ferror(stdin)) {
					pSeg->Release();
					return NULL;
				}
			}
			// Just return the amount of data we actually got. If it's zero for eof that's ok too.
			pSeg->Len(cbLen);
			return pSeg;
		}
	};

	/// \brief A CSink writing data to standard output
	class CSinkStdOut : public CSink {
	public:
		/// \brief Set file mode
		/// \param fBinary Set to true for binary mode writing
		/// \return A pointer to this
		CSinkStdOut *Init(bool fBinary = false) {
			ASSCHK(_setmode(_fileno(stdout), fBinary ? O_BINARY : O_TEXT) != -1, _T("CSourceStdOut::Init() setmode() failed"));
			return this;
		}

		// Set default mode (text)
		CSinkStdOut() {
			Init();
		}

		/// \brief output a segment
		/// Check with CError::GetErrorCode() and CError::GetErrorMsg() for errors
		/// \param pSeg The segment to write
		virtual void Out(CSeg *pSeg) {
			size_t cbLen = fwrite(pSeg->PtrRd(), 1, pSeg->Len(), stdout);
			if (cbLen != pSeg->Len()) {
				wchar_t buf[200];
				_wcserror_s(buf, sizeof(buf) / sizeof(buf[0]), errno);
				SetError(ERROR_CODE_GENERIC, _T("CSinkStdOut::fwrite failed [%s]"), buf);
			}
		}

		virtual bool OutClose() {
			fflush(stdout);
			return true;
		}
	};
} // namespace AxPipe;
#endif
