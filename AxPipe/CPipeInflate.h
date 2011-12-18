#pragma once
/*! \file
    \brief Declaration of AxPipe::Stock::CPipeInflate, Inflate stream with ZLib

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

    Why is this framework released as GPL and not LGPL?
    See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
    E-mail                          YYYY-MM-DD              Reason
    axpipe@axondata.se              2003-12-16              Initial
\endverbatim

    Ensure that the path to zlib.h is set in Include directories.
    define NO_GZIP, if you don't need that, in your project to decrease code size by about 10k
*/

#include "zlib.h"

namespace AxPipe {
    namespace Stock {
        /// \brief Decompress with ZLib
        ///
        /// Ensure that this file has an extra include directory so zlib.h is found.
        /// Also, either include the zlib project as a static or dynamic library, or
        /// manually include the following files for compilation with zlib 1.2.1:
        ///     inflate.c, adler32.c, crc32.c, inffast.c, inftrees.c, zutil.c
        ///
        /// If you define NO_GZIP, the executable shrinks and you don't need crc32.c,
        /// but you won't be able to default that format.
        class CPipeInflate : public CPipe {
            longlong m_cb;                  ///< Total number of bytes inflated.
            z_stream m_Zstream;             ///< ZLIB internal stream control structure
            unsigned long m_cbLastTotal_out; ///< ZLIB used for counting large stream sizes without touching z_stream
            unsigned long m_cbLastTotal_in; ///< ZLIB used for counting large stream sizes without touching z_stream
            CSeg *m_pOutSeg;                ///< Working segment
        public:
            typedef CPipe base;
            CPipeInflate();                 ///< Initialize member variables
            virtual ~CPipeInflate();        ///< Release segment if necessary
            bool OutOpen();                 ///< Initialize ZLib
            bool OutClose();                ///< Release segment if necessary
            void Out(CSeg *pSeg);           ///< Inflate each segment as it arrives
        };
    }
}
