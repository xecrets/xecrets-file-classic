#pragma once
/*! \file
	\brief Declaration of AxPipe::Stock::CPipeSHA1, calculate SHA1 of the stream

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
#include "TBits.h"

namespace AxPipe {
	namespace Stock {
		/// \brief A pass-through strainer, calculating an SHA1 on-the-fly.
		///
		/// You get the checksum by calling the GetHash() and the length of data hashed
		/// by calling CountBytes(). It can be used to calculate hashes for different parts
		/// of the stream by opening and closing with Open() and Close() respectively.
		///
		/// The Windows CryptoAPI implementation is actually quite a bit faster than the
		/// common public domain C implementation, it also occupies less space, so its
		/// used here.
		class CPipeSHA1 : public CPipe {
			unsigned __int64 m_cb;                  ///< Total bytes process in the hash
		protected:
			HCRYPTPROV m_hCryptProv;                ///< Provider handle, init in constructor
			HCRYPTHASH m_hHash;                     ///< Handle to the hash, init in OutOpen
			TBits<160> m_Hash;                      ///< SHA1 is 160 bits long.

			void Out(AxPipe::CSeg* pSeg);           ///< Consume the given segment, guaranteed to be non-NULL and non-zero-length.
			bool OutOpen();                         ///< Create and initialize the hash
			bool OutClose();                        ///< Finalize the hash
		public:
			CPipeSHA1();                            ///< Initialize crypto context etc
			virtual ~CPipeSHA1();

			unsigned __int64 CountBytes();          ///< Get total number of bytes processed for the hash
			unsigned char* GetHash();               ///< Get a pointer to the hash itself, 20 bytes
		};
	}
}
