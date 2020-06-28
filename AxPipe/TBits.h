#pragma once
/*! \file
	\brief Declaration of AxPipe::Stock::THash and AxPipe::Stock::TKey, template classes for such

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2020 Svante Seleborg/Axon Data, All rights reserved.

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

namespace AxPipe {
	namespace Stock {
		/// \brief A template class for hashes of various kinds.
		///
		/// Encapsulate common properities of hashes, mostly just for notational
		/// convenience.
		template <int iBits> class TBits {
			unsigned char m_Bits[iBits / 8];  ///< The bits. Yes, I know a char needn't be 8 bits
		public:
			TBits();                        ///< Construct zero-initialized
			TBits(unsigned char* bpInit,
				int cb);              ///< Byte-string initialized
			void* GetLeft(const int n);     ///< Get the n left-most bits (most significant)
			void* GetRight(const int n);    ///< Get the n right-most bits (least significant)

			TBits& operator+=(const TBits& rhs);    ///< Do long addition of two bit blocks.
			TBits& operator^=(const TBits& rhs);    ///< Do long xor of two bit blocks.
			TBits& operator=(const TBits& rhs);     ///< Assign one to another
		};
	}
}
