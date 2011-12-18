#pragma once
/*! \file
    \brief Declaration of AxPipe::Stock::CPipeDeflate, Deflate stream with ZLib

    @(#) $Id$

    AxPipe - Binary Stream Framework

    Copyright (C) 2005 Svante Seleborg/Axantum Software AB, All rights reserved.

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
    axpipe@axantum.com              2005-11-04              Initial
\endverbatim

    Ensure that the path to zlib.h is set in Include directories.
    define NO_GZIP, if you don't need that, in your project to decrease code size by about 10k
*/

#include "zlib.h"

namespace AxPipe {
    namespace Stock {
        /// \brief Compress with ZLib
        ///
        /// Ensure that this file has an extra include directory so zlib.h is found.
        /// Also, either include the zlib project as a static or dynamic library, or
        /// manually include the following files for compilation with zlib 1.2.1:
        ///     deflate.c, adler32.c, crc32.c, inffast.c, inftrees.c, zutil.c
        ///
        /// If you define NO_GZIP, the executable shrinks and you don't need crc32.c,
        /// but you won't be able to default that format.
        ///
        /// The compression strategy used here is to allocate a memory buffer
        /// m_cbChunkSize in size. This is always filled before output to the next
        /// stage. For each segment that is sent to us, we always consume it fully.
        /// If m_cbFlushInterval is non-zero, we output a full zlib Z_FULL_FLUSH
        /// with every time we have consumed that many bytes from the input. This allows
        /// decompression to recover, and a single error in the stream will at most
        /// result in that many lost bytes of source.
        /// There is always a one-to-one relation betweem m_pOutSeg's buffer and the
        /// buffer referred to by m_Zstream.
        /// We also provide zlib memory allocation stubs that use C++ 'new' and 'delete'
        /// to ensure that overrides of these are used for zlib too.
        class CPipeDeflate : public CPipe {
            typedef CPipe base;
        protected:
            longlong m_cbIn;                ///< Total number of bytes input for compression.
            longlong m_cbOut;               ///< Total number of bytes output after compression.
        private:
            bool m_fDeflate;                ///< True if we actually are doing deflation
            int m_nSaveRatioForCompress;    ///< Required ratio for compression to occur
            z_stream m_Zstream;             ///< ZLIB internal stream control structure
            unsigned long m_cbLastTotal_out; ///< ZLIB used for counting large stream sizes without touching z_stream
            unsigned long m_cbLastTotal_in; ///< ZLIB used for counting large stream sizes without touching z_stream
            CSeg *m_pOutSeg;                ///< Working segment
            size_t m_cbFlushInterval;       ///< The frequency of full flushes. 0 for never.
            size_t m_cbRemainBeforeFlush;   ///< The number of bytes to consume before the next flush.
            size_t m_cbChunkSize;           ///< The chunk we allocate for output at a time
        private:
            void AllocNew();                ///< Allocate a new buffer
            void SendOut();                 ///< Send this output buffer, and update statistics
            void InitZstream(z_stream *pZstream); ///< Basic init of the zlib structure
            int TryDeflateLoop(AxPipe::CSeg *pSeg, z_stream *pZstream); ///< The inner loop of the trial deflation
            size_t TryDeflate(const void *p, size_t cb); ///< Report the size of complete deflation of one memory block
            bool IsDeflatable(AxPipe::CSeg *pSeg, int nSaveRatioForCompress); ///< Determine if the ratio is sufficient
        public:
            CPipeDeflate();                 ///< Initialize member variables
            CPipeDeflate *Init(int nSaveRatioForCompress = 0, size_t cbChunkSize = 64*1024, size_t cbFlushInterval = 64*1024); ///< Initialize
            virtual ~CPipeDeflate();        ///< Release segment if necessary
            bool OutOpen();                 ///< Initialize ZLib
            bool OutClose();                ///< Release segment if necessary
            void Out(CSeg *pSeg);           ///< Inflate each segment as it arrives
            longlong GetOutputSize();       ///< The number of bytes sent
            longlong GetInputSize();        ///< The number of bytes received
            bool IsDeflating();             ///< True if we're actually deflating
        };
    }
}
