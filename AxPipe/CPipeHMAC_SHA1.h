#pragma once
/*! \file
	\brief Declaration of AxPipe::Stock::CPipeHMAC_SHA1, calculate HMAC_SHA1 of the stream

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

	Why is this framework released as GPL and not LGPL?
	See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-15              Initial
\endverbatim
*/
#include <wincrypt.h>
#include "TBits.h"
#include "CPipeSHA1.h"

namespace AxPipe {
	namespace Stock {
		/// \brief Calculate HMAC-SHA1-128 or 160 from a data-stream
		///
		/// Define the bitlength in the template instantiation.
		template <int iBits> class CPipeHMAC_SHA1 : public CPipeSHA1 {
			TBits<160> m_HMAC;              ///< HMAC intermediate
			TBits<iBits> m_Key;             ///< The key provied in Init()
			size_t m_cbOffset;              ///< Offset from where to start HMAC'ing.
			void XorPad(unsigned char oPad);///< Helper for the inner and outer padding and Xor
		protected:
			void Out(CSeg* pSeg);           ///< Hash and pass onwards
			bool OutOpen();                 ///< Do the inner wrap
			bool OutClose();                ///< Do the outer wrap
		public:
			/// \brief Initialize the key and possibly an offset when to start HMAC'ing
			CPipeHMAC_SHA1<iBits>* Init(TBits<iBits>* pKey, size_t cbOffset = 0);
		};
	}
}
