#ifndef CFILEMAP_H
#define CFILEMAP_H
/*! \file CFileMap.h
    \brief Memory Mapped File Source and Sink, AxPipe::CSourceMemFile and AxPipe::CSinkMemFile

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
    CFileMap.h                      Memory Mapped File Source and Sink

    E-mail                          YYYY-MM-DD              Reason
    axpipe@axondata.se              2003-11-23              Initial
\endverbatim

    AxPipe file source and sink classes, implemented using memory mapping

    C[T]SourceMemFile  - a source [in it's own thread]
    C[T]SinkMemFile]   - a sink [in it's own thread]

    Copyright 2003, Axon Data/Svante Seleborg, All Rights Reserved.
*/
#include    "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CFileMap.h"

namespace AxPipe {
/// \brief A special purpose version of CSeg, to work with Memory Mapped segments.
///
/// CSegMap is able to release a view instead of delete'ing upon destruction.
/// It also implements run time typing to distinguish it, as well as an owner
/// mechanism whereby a class can tag and subsequently recognize a segment as
/// on that it 'owns' and thus handles.
///
/// The actual mapping of the file is handled outside of this class, but it can,
/// and will, unmap the view.
/// \todo Bring together the MapUserView() functionality into the constructor here,
/// it really makes no sense to have it done outside. It just happended that way
/// due to historic reasons.
class CSegMap : public CSeg {
    longlong m_llPos;                       ///< The file position in the backing file of the segment.
    void *m_pView;                          ///< The corresponding mapped view
    void *m_pOwner;                         ///< Implement owner-id functions, opaque owner id here.

public:
    /// \brief Construct with Owner, size, buffer pointer, view, file pos and possibly readonly
    CSegMap(void *pOwner, size_t cb, void *pv, void *pView, longlong llPos, bool fReadOnly = false);
    virtual ~CSegMap();                     ///< Unmap the view, if any.
    longlong GetPos();                      ///< Get the corresponding file pointer

public:
    static void *ClassId();                 ///< Compile time polymorphic type information
    virtual void *RTClassId();              ///< Run time polymorphic type information
    bool IsOwner(void *pOwner);             ///< Check if the provided opaque pointer matches the owner given on construction.
};

/// \brief A CSource providing data from a file system file, using memory mapping.
class CSourceMemFile : public CSource {
    HANDLE m_hFile,                         ///< The opened file
           m_hMapping;                      ///< The mapping of the file
    size_t m_cbChunk;                       ///< The chunk size we send down stream
    longlong m_cbFileSize,                  ///< The length of the file in bytes
             m_cbStreamPos;                 ///< The next file position to read a chunk from
    _TCHAR *m_szFileName;                   ///< The provided file name, new[]'d and delete[]'d here

protected:
    HANDLE GetHandle();                     ///< Get the handle to the opened file

public:

    /// \brief Set file and chunk size
    CSourceMemFile *Init(const _TCHAR *szFileName, size_t cbChunk = 64*1024);
    CSourceMemFile();                       ///< Just initialize member variables
    virtual ~CSourceMemFile();              ///< Additional destruction necessary...

protected:
    bool OutOpen();                         ///< Open the file and create a mapping
    bool OutClose(void);                    ///< Close the file and the mapping
    CSeg *In();                             ///< Get the next chunk from the input file
};

/// \brief A Threaded version of CSourceMemFile for convenience.
typedef CThread<CSourceMemFile> CTSourceMemFile;

/// \brief A CSink implemented with a memory mapped file as the destination.
class CSinkMemFile : public CSink {
    HANDLE m_hFile,                         ///< The opened file
           m_hMapping;                      ///< The mapping of the file
    size_t m_cbChunk;                       ///< The chunk size we send down stream
    longlong m_cbFileSize,                  ///< The length of the file in bytes
             m_cbStreamPos;                 ///< The next file position to read a chunk from
    _TCHAR *m_szFileName;                   ///< The provided file name, new[]'d and delete[]'d here
    longlong m_cbInPos,                     ///< The file pointer position to get the next segment to write to
             m_cbOutPos,                    ///< The file pointer position to write the next output to
             m_cbMappingSize;               ///< The size of the current mapping - changed dynamically
    CRITICAL_SECTION m_CritSect;            ///< Threading protection for certain code sections

protected:
    HANDLE GetHandle();                     ///< Get the handle to the opened file

public:
    /// \brief Set file and chunk size
    CSinkMemFile *Init(const TCHAR *szFileName, size_t cbChunk = 64*1024);
    CSinkMemFile();                         ///< Initialize member variables etc.
    virtual ~CSinkMemFile();                ///< Additional destruction necessary...

protected:
    bool OutClose();                        ///< Close the file, as well as all mappings, set end of file etc.
    CSeg *OutGetSeg(size_t cb);             ///< Get a writeable segment, mapped to the output file if possible.
    void Out(CSeg *pSeg);                   ///< Write a segment to the file, optimizing the case where it already is a mapping.
    bool OutOpen();                         ///< Open the file named in Init() for output
};

/// \brief A threaded version of CSinkMemFile for convenience.
typedef CThread<CSinkMemFile> CTSinkMemFile;

} // namespace AxPipe
#endif  CFILEMAP_H
