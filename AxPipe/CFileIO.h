#ifndef CFILEIO_H
#define CFILEIO_H
/*! \file CFileIO.h
    \brief Regular Win32 File IO Source and Sink, AxPipe::CSourceFileIO and AxPipe::CSinkFileIO

    @(#) $Id$

    AxPipe - Binary Stream Framework

    Copyright (C) 2005 Svante Seleborg/Axon Data, All rights reserved.

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
    CFileIO.h                       Win32 File IO Source and Sink

    E-mail                          YYYY-MM-DD              Reason
    axpipe@axantum.com              2005-05-18              Initial
\endverbatim

    AxPipe file source and sink classes, implemented using regular Win32 IO

    C[T]SourceFileIO  - a source [in it's own thread]
    C[T]SinkFileIO   - a sink [in it's own thread]

    Copyright 2005, Axon Data/Svante Seleborg, All Rights Reserved.
*/
#include    "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CFileIO.h"

namespace AxPipe {
    /// \brief A common base for FileIO source and sink
    template<class T> class CFileIOBase : public T {
    protected:
        HANDLE m_hFile;                     ///< The opened file
        /// \brief Get the handle to the opened file
        /// \return An operating system handle to the open file.
        HANDLE
        GetHandle() {
            return m_hFile;
        }

        /// \brief Get the current size of the file.
        longlong
        FileSize() {
            // We do this the hard way, because GetFileSizeEx is not supported on win98.
            LARGE_INTEGER li;
            // The really hardway, since GetFileSize seems to be wrongly defined. The second parameter is PDWORD, but should
            // really be PLONG (compare SetFilePointer).
            DWORD dwHigh;
            li.LowPart = ::GetFileSize(m_hFile, &dwHigh);
            if (li.LowPart == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
                SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::Can't get size of file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
            }
            li.HighPart = dwHigh;
            return static_cast<longlong>(li.QuadPart);
        }
    };

    class CSinkFileIO;                      // Forward
    /// \brief A CSource providing data from a file system file, using Win32 File IO
    class CSourceFileIO : public CFileIOBase<CSource>  {
        typedef CFileIOBase<CSource> base;  ///< The base class

        size_t m_cbChunk;                   ///< The chunk size we send down stream
        longlong m_cbFileSize,              ///< The length of the file in bytes
                m_cbStreamPos;              ///< The next file position to read a chunk from
        _TCHAR *m_szFileName;               ///< The provided file name, new[]'d and delete[]'d here

    protected:
        /// \brief Get the size of the opened file
        /// \return The size in bytes of the opened file
        longlong FileSize() { return m_cbFileSize; }

    public:
        /// \brief Set file and chunk size
        CSourceFileIO *Init(const _TCHAR *szFileName, size_t cbChunk = 64*1024);
        /// \brief Use an open sink as the source instead. Must be used in/before OutClose() of the sink
        CSourceFileIO *Init(CSinkFileIO *pSink, size_t cbChunk = 64*1024);
        CSourceFileIO();                    ///< Just initialize member variables
        virtual ~CSourceFileIO();           ///< Additional destruction necessary...
        const _TCHAR *GetFilePath();        ///< Get the used file path

    protected:
        bool OutOpen();                     ///< Open the file
        bool OutClose(void);                ///< Close the file
        CSeg *In();                         ///< Get the next chunk from the input file
    };

    /// \brief A Threaded version of CSourceFileIO for convenience.
    typedef CThread<CSourceFileIO> CTSourceFileIO;

    /// \brief A CSink implemented with a Win32 file as the destination.
    class CSinkFileIO : public CFileIOBase<CSink> {
        typedef CFileIOBase<CSink> base;   ///< The base class

        friend CSourceFileIO;

        size_t m_cbChunk;                   ///< The chunk size we send down stream
        _TCHAR *m_szFileName;               ///< The provided file name, new[]'d and delete[]'d here
        longlong m_cbOutPos;                ///< The file pointer position to write the next output to

    protected:
        void SetFilePos(longlong i);        ///< Set the file pointer. Do not truncate.
        void SetFileEnd();                  ///< Truncate the file at the current position.

    public:
        /// \brief Set file and chunk size
        CSinkFileIO *Init(const TCHAR *szFileName, size_t cbChunk = 64*1024);
        CSinkFileIO();                      ///< Initialize member variables etc.
        virtual ~CSinkFileIO();             ///< Additional destruction necessary...
        const _TCHAR *GetFilePath();        ///< Get the used file path

    protected:
        bool OutClose();                    ///< Close the file, set end of file etc.
        void Out(CSeg *pSeg);               ///< Write a segment to the file, optimizing the case where it already is a mapping.
        bool OutOpen();                     ///< Open the file named in Init() for output
    };

    /// \brief A threaded version of CSinkFileIO for convenience.
    typedef CThread<CSinkFileIO> CTSinkFileIO;

} // namespace AxPipe
#endif  CFILEIO_H
