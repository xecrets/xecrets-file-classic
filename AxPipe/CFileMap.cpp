/*! \file
    \brief Implementation of AxPipe::CSourceFileMap and AxPipe::CSinkFileMap, memory mapped files

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
    CFileMap.cpp                    Implementation of CSourceFileMap and CSinkFileMap, memory mapped files

    E-mail                          YYYY-MM-DD              Reason
    axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"
#include "CFileMap.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CFileMap.cpp"

namespace AxPipe {
    /// \brief Map a view of a file to a given offset.
    ///
    /// Ensure that the view is correctly aligned, but give the caller a convenient
    /// pointer to the right place in the view.
    /// \param hMapping An active file mapping
    /// \param llOffset The offset in the file you want the view to start at
    /// \param cbLen The length of the asked for view
    /// \param ppvUserView A user-friendly pointer into the view, correctly offset.
    /// \param dwAccess Access requested, FILE_MAP_READ or FILE_MAP_WRITE typeically
    /// \return The actual view, NULL if error.
    static void *
    MapUserView(HANDLE hMapping, longlong llOffset, size_t cbLen, void **ppvUserView, DWORD dwAccess) {
        static DWORD dwAllocationGranularity;

        if (ppvUserView == NULL) {
            return NULL;
        }

        // Get system allocation granularity to use with the memory mapping functions
        if (!dwAllocationGranularity) {
            SYSTEM_INFO SystemInfo;
            GetSystemInfo(&SystemInfo); // No error return!
            dwAllocationGranularity = SystemInfo.dwAllocationGranularity;
        }

        DWORD dwMisAlign = (DWORD)(llOffset % dwAllocationGranularity);
        cbLen += dwMisAlign;
        llOffset -= dwMisAlign;

        void *vpView = MapViewOfFile(hMapping, dwAccess, (*(LARGE_INTEGER*)&llOffset).HighPart, (*(LARGE_INTEGER*)&llOffset).LowPart, cbLen);
        ASSAPI(vpView != NULL);
        *ppvUserView = (char *)vpView + dwMisAlign;
        return vpView;
    }
    /// \brief Construct with Owner, size, buffer pointer, view, file pos and possibly readonly
    /// \param pOwner An opaque value identifying the 'owner', probably a 'this' pointer.
    /// \param cb The size of the provided memory mapped file segment
    /// \param pv The pointer to the actual data to be used
    /// \param pView The view pointer, pv may be offset from this due to alignment.
    /// \param llPos The file pointer of this segment.
    /// \param fReadOnly True if this is a read-only segment
    CSegMap::CSegMap(void *pOwner, size_t cb, void *pv, void *pView, longlong llPos, bool fReadOnly) : CSeg(cb, pv, fReadOnly) {
        m_pView = pView;
        m_pOwner = pOwner;
        m_llPos = llPos;
    }

    /// \brief Unmap the view, if any.
    CSegMap::~CSegMap() {
        if (m_pView) {
            UnmapViewOfFile(m_pView);
            m_pView = NULL;
        }
    }
    
    /// \brief Get the corresponding file pointer
    /// \return A position in the mapped file.
    longlong
    CSegMap::GetPos() {
        return m_llPos;
    }

    /// \brief Compile time polymorphic type information
    /// \see CSeg::ClassId()
    void *
    CSegMap::ClassId() {
        static int i;
        return &i;
    }

    /// \brief Run time polymorphic type information
    /// \see CSeg::RTClassId()
    void *
    CSegMap::RTClassId() {
        return ClassId();
    }
    
    /// \brief Check if the provided opaque pointer matches the owner given on construction.
    /// \param pOwner An opaque pointer valute, probably a 'this' pointer
    /// \return true if the same value was provided as owner on construction.
    bool
    CSegMap::IsOwner(void *pOwner) {
        return m_pOwner == pOwner;
    }

    /// \brief Just initialize member variables
    CSourceMemFile::CSourceMemFile() {
        m_szFileName = NULL;
        m_hFile = INVALID_HANDLE_VALUE;
        m_hMapping = NULL;
    }

    /// \brief Additional destruction necessary...
    CSourceMemFile::~CSourceMemFile() {
        delete [] m_szFileName;
    }

    /// \brief Get the handle to the opened file
    /// \return An operating system handle to the open file.
    HANDLE
    CSourceMemFile::GetHandle() {
        return m_hFile;
    }

    /// \brief Set file and chunk size
    /// \param szFileName The name of the file, it is copied and saved here.
    /// \param cbChunk The size of the chunks we send downstream
    /// \return A pointer to 'this' CSourceMemFile
    CSourceMemFile *CSourceMemFile::Init(const _TCHAR *szFileName, size_t cbChunk) {
        m_cbChunk = cbChunk;
        size_t cbLen = lstrlen(szFileName);
        CopyMemory(m_szFileName = new _TCHAR[cbLen+1], szFileName, (cbLen + 1) * sizeof (_TCHAR));
        return this;
    }

    /// \brief Open the file and create a mapping
    ///
    /// The filename is provided in the Init() call.
    /// Check for error with GetErrorCode().
    /// \return true if we are to propagate, which we do if no error occurred. false is not an error indication though.
    bool CSourceMemFile::OutOpen() {
        m_hFile = CreateFile(m_szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (m_hFile == INVALID_HANDLE_VALUE) {
            SetError(ERROR_CODE_GENERIC, _T("CSourceMemFile::CSourceMemFile open error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
            return false;                   // No point propagating if we already failed
        }
        ((LARGE_INTEGER *)&m_cbFileSize)->LowPart =
            GetFileSize(m_hFile, (LPDWORD)&(((LARGE_INTEGER *)&m_cbFileSize)->HighPart));
        m_cbStreamPos = 0;
        m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!m_hMapping) {
            SetError(ERROR_CODE_GENERIC, _T("CSourceMemFile::CSourceMemFile failed to create file mapping [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
            return false;                   // No use propagating of we already failed.
        }
        return true;
    }

    /// \brief Close the file and the mapping
    ///
    /// Check for error with GetErrorCode().
    /// \return true if propagation of the close is recommended, which it is if no error. false is not error indication though.
    bool CSourceMemFile::OutClose(void) {
        if (m_hMapping) {
            if (!CloseHandle(m_hMapping)) {
                SetError(ERROR_CODE_GENERIC, _T("CSourceMemFile::Close failed to close mapping [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                return true;
            }
            m_hMapping = NULL;
        }
        if (m_hFile != INVALID_HANDLE_VALUE) {
            if (!CloseHandle(m_hFile)) {
                SetError(ERROR_CODE_GENERIC, _T("CSourceMemFile::Close failed to close file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                return true;
            }
            m_hFile = INVALID_HANDLE_VALUE;
        }
        return true;
    }
    /// \brief Get the next chunk from the input file
    ///
    /// The segment returned is actually a CSegMem, i.e. a mapping to the actual
    /// file - we do not copy to a memory buffer.
    ///
    /// Multiple calls on EOF conditions are allowed.
    ///
    /// \return A chunk, or zero-length on End-Of-File, or NULL on error.
    CSeg *CSourceMemFile::In() {
        if (m_cbStreamPos == m_cbFileSize) {
            return new CSeg;    // Return a zero-sized segment.
        }
        size_t cbThisChunk = m_cbChunk;
		if (m_cbStreamPos + static_cast<AxPipe::longlong>(cbThisChunk) > m_cbFileSize) {
            cbThisChunk = (size_t)(m_cbFileSize - m_cbStreamPos);
        }

        void *pView, *pUserView;
        pView = MapUserView(m_hMapping, m_cbStreamPos, cbThisChunk, &pUserView, FILE_MAP_READ);
        CSeg *pSeg = new CSegMap(NULL, cbThisChunk, pUserView, pView, m_cbStreamPos, true);
        m_cbStreamPos += cbThisChunk;
        return pSeg;
    }

    /// \brief Initialize member variables etc.
    CSinkMemFile::CSinkMemFile() {
        m_szFileName = NULL;
        m_hFile = INVALID_HANDLE_VALUE;
        m_hMapping = NULL;
        InitializeCriticalSection(&m_CritSect);
        m_cbOutPos = m_cbInPos = 0;
    }

    /// \brief Additional destruction necessary...
    CSinkMemFile::~CSinkMemFile() {
        delete[] m_szFileName;
        DeleteCriticalSection(&m_CritSect);
    }

    /// \brief Get the handle to the opened file
    /// \return An operating system handle to the open file.
    HANDLE
    CSinkMemFile::GetHandle() {
        return m_hFile;
    }

    /// \brief Set file and chunk size
    /// \param szFileName The name of the file, it is copied and saved here.
    /// \param cbChunk The size of the chunks we provide upon request via OutGetSeg() upstream.
    /// \return A pointer to 'this' CSourceMemFile
    CSinkMemFile *
    CSinkMemFile::Init(const TCHAR *szFileName, size_t cbChunk) {
        m_cbChunk = cbChunk;
        size_t cbLen = lstrlen(szFileName);
        CopyMemory(m_szFileName = new _TCHAR[cbLen+1], szFileName, (cbLen + 1) * sizeof (_TCHAR));
        return this;
    }

    /// \brief Close the file, as well as all mappings, set end of file etc.
    ///
    /// Check for errors with GetErrorCode()
    /// \return true to propagate the close.
    bool
    CSinkMemFile::OutClose() {
        if (m_hMapping) {

            if (CloseHandle(m_hMapping)) {
                m_hMapping = NULL;
            } else {
                SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Close failed to close mapping [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
            }
        }
        if (m_hFile != INVALID_HANDLE_VALUE) {
            //
            //  Set end of file pointer, this is determined by m_cbOutPos
            //
            if (SetFilePointer(m_hFile, ((LARGE_INTEGER *)&m_cbOutPos)->LowPart, &((LARGE_INTEGER *)&m_cbOutPos)->HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
                SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Close set file pointer to end failed [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                return true;
            }
            if (!SetEndOfFile(m_hFile)) {
                SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Close can't set end of file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                return true;
            }
            if (!CloseHandle(m_hFile)) {
                SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Close failed to close file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                return true;
            }
            m_hFile = INVALID_HANDLE_VALUE;
        }
        return true;
    }
    /// \brief Get a writeable segment, mapped to the output file if possible.
    ///
    /// Map a request for an output segment directly to the output file. If necessary,
    /// re-create a mapping to a possibly extended file.
    ///
    /// For this to be useful, the upstream caller must get segments in the same
    /// sequence that they are output, and also keep them the same size, i.e. not
    /// get a segment and then change the CSeg::Len() or CSeg::Drop() bytes off it.
    /// In fact using CSeg::Drop() will cause undefined effects. Shortening is
    /// possible, but strongly recommended against, as it will make the code quite
    /// inefficient.
    /// \param cb The size in bytes of the segment to get.
    /// \return A (possibly memory mapped) pointer to a CSeg of the requested size.
    CSeg *
    CSinkMemFile::OutGetSeg(size_t cb) {
        CSeg *pSeg;

        EnterCriticalSection(&m_CritSect);
        // We can only get a mapped segment if we have an open file already.
        longlong cbPos = m_cbInPos > m_cbOutPos ? m_cbInPos : m_cbOutPos;
        if (m_hFile != INVALID_HANDLE_VALUE) {
			if (cbPos + static_cast<AxPipe::longlong>(cb) > m_cbMappingSize) {
                m_cbMappingSize = cbPos + cb;
                if (m_hMapping) {
                    // This actually works even if we have open views, the order
                    // of calls to unmapview and closehandle is not important.
                    if (!CloseHandle(m_hMapping)) {
                        SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::OutGetSeg failed to close mapping [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                        LeaveCriticalSection(&m_CritSect);
                        return NULL;
                    }
                    m_hMapping = NULL;
                }
            }
            if (!m_hMapping) {
                // Now create a mapping that is large enough for the largest stream to date.
                m_hMapping = CreateFileMapping(m_hFile, NULL, PAGE_READWRITE, ((LARGE_INTEGER *)&m_cbMappingSize)->HighPart, ((LARGE_INTEGER *)&m_cbMappingSize)->LowPart, NULL);
                if (!m_hMapping) {
                    SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::OutGetSeg failed to create file mapping [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                    LeaveCriticalSection(&m_CritSect);
                    return NULL;
                }
            }
            void *pView, *pUserView;
            pView = MapUserView(m_hMapping, cbPos, cb, &pUserView, FILE_MAP_WRITE|FILE_MAP_READ);
            pSeg = new CSegMap(this, cb, pUserView, pView, cbPos);
        } else {
            pSeg = new CSeg(cb);
        }
        m_cbInPos = cbPos + cb;
        LeaveCriticalSection(&m_CritSect);
        return pSeg;
    }
    /// \brief Write a segment to the file, optimizing the case where it already is a mapping.
    ///
    /// Write a segment to the file by copying into a memory mapped segment, unless
    /// we're already such a segment, in which case we actually need do nothing except
    /// keep track of the length of valid data 'written'.
    /// \param pSeg The segment, possibly actually a CSegMap, determined by run time type info.
    void
    CSinkMemFile::Out(CSeg *pSeg) {
        if (CSeg::IsSeg(pSeg)) {
            // We need to be in a critical section, since the previous section of
            // the pipe may be in a different thread and may request allocation from
            // OutGetSeg().
            EnterCriticalSection(&m_CritSect);
            if (pSeg->Len()) {
                // If this is not a CSegMap, or if it is, we're not the owner then we allocate an output.
                if ((pSeg->RTClassId() != CSegMap::ClassId()) || !((CSegMap *)pSeg)->IsOwner(this)) {
                    CSeg *pOutSeg = OutGetSeg(pSeg->Len());
                    if (!pOutSeg) {
                        SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Out() [OutGetSeg() returned NULL]"));
                    } else {
                        CopyMemory(pOutSeg->PtrWr(), pSeg->PtrRd(), pSeg->Len());
                        pOutSeg->Release();
                    }
                } else {
                    // If we're 'short' of data in the output, we move the segment
                    // back. This can happen if an earlier requested segment was cut
                    // short before being output.
                    CSegMap *pSegMap = (CSegMap *)pSeg;
                    if (pSegMap->GetPos() > m_cbOutPos) {
                        void *pView, *pUserView;
                        pView = MapUserView(m_hMapping, m_cbOutPos, pSegMap->Len(), &pUserView, FILE_MAP_WRITE|FILE_MAP_READ);
                        if (!pView) {
                            SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Out() [MapUserView() returned NULL]"));
                        } else {
                            CopyMemory(pUserView, pSegMap->PtrRd(), pSegMap->Len());
                            if (!(UnmapViewOfFile(pView))) {
                                SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Out() [UnmapViewOfFile() failed: %s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
                            }
                        }
                    } else if (pSegMap->GetPos() < m_cbOutPos) {
                        // If we've already output into this segment, it's run over and
                        // we've violated the stream model. This can happen if a non-mapped
                        // segment is gotten, and then before it's 'output', a non-mapped
                        // segment is output. This is an error condition.
                        SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::Out() [Output sequence error]"));
                    }
                    // If (which is the normal case) the output-position is the same as the
                    // segment's start, everything is ok and we do nothing.
                }
            }
            m_cbOutPos += pSeg->Len();
            pSeg->Release();
            LeaveCriticalSection(&m_CritSect);
        }
    }
    /// \brief Open the file named in Init() for output
    ///
    /// Check for errors with GetErrorCode().
    /// \return true to propagate the open, which we do if no error. false is not an error condition.
    bool
    CSinkMemFile::OutOpen() {
        // If it's there, open for writing, otherwise create it.
        m_hFile = CreateFile(m_szFileName, GENERIC_WRITE|GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (m_hFile == INVALID_HANDLE_VALUE) {
            SetError(ERROR_CODE_GENERIC, _T("CSinkMemFile::CSinkMemFile open error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
        }
        ((LARGE_INTEGER *)&m_cbMappingSize)->LowPart = GetFileSize(m_hFile, (LPDWORD)&(((LARGE_INTEGER *)&m_cbMappingSize)->HighPart));
        m_cbOutPos = m_cbInPos = 0;
        return true;
    }
};
