#pragma once
/*! \file
\brief Implementation of AxPipe::Stock::CPipeDeflate

@(#) $Id$

AxPipe - Binary Stream Framework

Copyright (C) 2005-2023 Svante Seleborg/Axon Data, All rights reserved.

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

#include "AxPipe.h"

namespace AxPipe {
	namespace Stock {
		/// \brief Convert a Unicode stream to Ansi, kind of. Actually just
		/// truncate.
		///
		/// To simplify the logic we use a filter that passes us bytes in
		/// groups of two.
		class CPipeUnicodeToAnsi : public CPipeBlock {
		public:
			/// \brief Initialize member variables and the base class
			CPipeUnicodeToAnsi() {
				CPipeBlock::Init(sizeof(wchar_t));
			}

			/// \brief Called at the end of one file's data stream
			///
			/// This is where we detect if there is some internal inconsistency
			/// between expected byte count and actual.
			/// \return true to pass the Close() call down the line.
			bool OutClose() {
				if (PartialBlock()) {
					SetError(ERROR_CODE_DERIVED, _T("Partial block detected in UnicodeToAnsi"));
				}
				return true;
			}

			/// \brief Decrypt a block and pass it along
			///
			/// Padding is removed, only actual plain text is passed along.
			/// \param pSeg The data to consume. Note that we're guaranteed a multiple of the block size here.
			void Out(CSeg* pSeg) {
				// Here we're guaranteed an even multiple of the block size requested.
				wchar_t* unicode = (wchar_t*)pSeg->PtrRd();
				CSeg* pAnsiSeg = new CSeg(pSeg->Len() / (sizeof(wchar_t) / sizeof(char)));
				for (int i = 0; i < pAnsiSeg->Len(); ++i) {
					pAnsiSeg->PtrWr()[i] = (char)unicode[i];
				}

				pSeg->Release();
				Pump(pAnsiSeg);
			}
		};
	}
}