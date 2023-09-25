/*! \file
	\brief Implementation of AxPipe::CSourceFileIO and AxPipe::CSinkFileIO, Win32 File IO

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2023 Svante Seleborg/Axon Data, All rights reserved.

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
	CFileIO.cpp                     Implementation of CSourceFileIO and CSinkFileIO, Win32 files

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2005-05-18              Initial
\endverbatim
*/
#include "stdafx.h"
#include "CFileIO.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CFileIO.cpp"

namespace AxPipe {
	/// \brief Just initialize member variables
	CSourceFileIO::CSourceFileIO() {
		m_szFileName = NULL;
		m_hFile = INVALID_HANDLE_VALUE;
	}

	/// \brief Additional destruction necessary...
	CSourceFileIO::~CSourceFileIO() {
		delete[] m_szFileName;
	}

	/// \brief Get the file path used
	/// \return A pointer to the path used. Owned by this class. Deleted here.
	const _TCHAR*
		CSourceFileIO::GetFilePath() {
		return m_szFileName;
	}

	/// \brief Set file and chunk size
	/// \param szFileName The name of the file, it is copied and saved here.
	/// \param cbChunk The size of the chunks we send downstream
	/// \return A pointer to 'this' CSourceFileIO
	CSourceFileIO* CSourceFileIO::Init(const _TCHAR* szFileName, size_t cbChunk) {
		m_cbChunk = cbChunk;
		size_t cbLen = lstrlen(szFileName);
		CopyMemory(m_szFileName = new _TCHAR[cbLen + 1], szFileName, (cbLen + 1) * sizeof(_TCHAR));
		return this;
	}

	/// \brief Use an open sink as the source instead. Must be used in/before OutClose() of the sink
	/// \param pSink Pointer to a CSinkFileIO, must be open.
	/// \param cbChunk The size of the chunks we send downstream
	/// \return A pointer to 'this' CSourceFileIO
	CSourceFileIO* CSourceFileIO::Init(CSinkFileIO* pSink, size_t cbChunk) {
		// Use a duplicate of the handle, so we can close it normally
		if (DuplicateHandle(GetCurrentProcess(), pSink->m_hFile, GetCurrentProcess(), &m_hFile, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
			SetError(ERROR_CODE_GENERIC, _T("CSourceFileIO::CSourceFileIO DuplicateHandle error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(pSink->m_szFileName)).get());
			return this;
		}
		return Init(pSink->m_szFileName, cbChunk);
	}

	/// \brief Open the file
	///
	/// The filename is provided in the Init() call.
	/// Check for error with GetErrorCode().
	/// \return true if we are to propagate, which we do if no error occurred. false is not an error indication though.
	bool CSourceFileIO::OutOpen() {
		if (m_hFile == INVALID_HANDLE_VALUE) {
			m_hFile = CreateFile(m_szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
			if (m_hFile == INVALID_HANDLE_VALUE) {
				SetError(ERROR_CODE_GENERIC, _T("CSourceFileIO::CSourceFileIO open error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
				return false;                   // No point propagating if we already failed
			}
		}
		// Find out how large the file is
		m_cbFileSize = base::FileSize();
		if (GetErrorCode() != ERROR_CODE_SUCCESS) {
			return false;                   // No point propagating if we already failed
		}

		LARGE_INTEGER li = { 0 };
		// Get the current location in the file - normally zero, but just to be careful since we may be re-using an open handle
		// Do this the hard way with SetFilePointer since we want to run on Windows 98
		if (SetFilePointer(m_hFile, li.LowPart, &li.HighPart, FILE_CURRENT) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
			SetError(ERROR_CODE_GENERIC, _T("CSourceFileIO::CSourceFileIO SetFilePointer error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
			return false;                   // No point propagating if we already failed
		}
		m_cbStreamPos = li.QuadPart;
		return true;
	}

	/// \brief Close the file
	///
	/// Check for error with GetErrorCode().
	/// \return true if propagation of the close is recommended, which it is if no error. false is not error indication though.
	bool CSourceFileIO::OutClose(void) {
		if (m_hFile != INVALID_HANDLE_VALUE) {
			if (!CloseHandle(m_hFile)) {
				SetError(ERROR_CODE_GENERIC, _T("CSourceFileIO::Close failed to close file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
				return true;
			}
			m_hFile = INVALID_HANDLE_VALUE;
		}
		return true;
	}

	/// \brief Get the next chunk from the input file
	///
	/// Multiple calls on EOF conditions are allowed.
	///
	/// \return A chunk, or zero-length on End-Of-File, or NULL on error.
	CSeg* CSourceFileIO::In() {
		if (m_cbStreamPos == m_cbFileSize) {
			return new CSeg;    // Return a zero-sized segment.
		}
		size_t cbThisChunk = m_cbChunk;
		if (m_cbStreamPos + static_cast<AxPipe::longlong>(cbThisChunk) > m_cbFileSize) {
			cbThisChunk = (size_t)(m_cbFileSize - m_cbStreamPos);
		}
		DWORD cbBytesRead = 0;
		CSeg* pSeg = new CSeg(cbThisChunk);
		ASSPTR(pSeg);

		if (!ReadFile(m_hFile, pSeg->PtrWr(), (DWORD)cbThisChunk, &cbBytesRead, FALSE)) {
			SetError(ERROR_CODE_GENERIC, _T("CSourceFileIO::In() failed to read file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
		}

		m_cbStreamPos += cbBytesRead;
		return pSeg;
	}

	/// \brief Initialize member variables etc.
	CSinkFileIO::CSinkFileIO() {
		m_szFileName = NULL;
		m_hFile = INVALID_HANDLE_VALUE;
		m_cbOutPos = 0;
	}

	/// \brief Additional destruction necessary...
	CSinkFileIO::~CSinkFileIO() {
		delete[] m_szFileName;
	}

	/// \brief Get the file path used
	/// \return A pointer to the path used. Owned by this class. Deleted here.
	const _TCHAR*
		CSinkFileIO::GetFilePath() {
		return m_szFileName;
	}

	/// \brief Set the file pointer. Do not truncate.
	void
		CSinkFileIO::SetFilePos(longlong i) {
		LARGE_INTEGER li;
		li.QuadPart = i;
		if (::SetFilePointer(m_hFile, li.LowPart, &li.HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
			SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::SetFilePointer failed [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
		}
		m_cbOutPos = i;
	}

	/// \brief Set the end-of-file pointer at the current position.
	void
		CSinkFileIO::SetFileEnd() {
		if (!::SetEndOfFile(m_hFile)) {
			SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::Can't set end of file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
		}
	}

	/// \brief Set file and chunk size
	/// \param szFileName The name of the file, it is copied and saved here.
	/// \param cbChunk The size of the chunks we provide upon request via OutGetSeg() upstream.
	/// \return A pointer to 'this' CSinkFileIO
	CSinkFileIO*
		CSinkFileIO::Init(const TCHAR* szFileName, size_t cbChunk) {
		m_cbChunk = cbChunk;
		size_t cbLen = lstrlen(szFileName);
		CopyMemory(m_szFileName = new _TCHAR[cbLen + 1], szFileName, (cbLen + 1) * sizeof(_TCHAR));
		return this;
	}

	/// \brief Close the file, as well as all mappings, set end of file etc.
	///
	/// Check for errors with GetErrorCode()
	/// \return true to propagate the close.
	bool
		CSinkFileIO::OutClose() {
		if (m_hFile != INVALID_HANDLE_VALUE) {
			//  Set end of file pointer
			//
			if (!::SetEndOfFile(m_hFile)) {
				SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::Close can't set end of file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
				return true;
			}
			if (!::CloseHandle(m_hFile)) {
				SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::Close failed to close file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
				return true;
			}
			m_hFile = INVALID_HANDLE_VALUE;
		}
		return true;
	}

	/// \brief Write a segment to the file
	/// \param pSeg The segment
	void
		CSinkFileIO::Out(CSeg* pSeg) {
		DWORD cbBytesWritten;
		if (!::WriteFile(m_hFile, pSeg->PtrRd(), (DWORD)pSeg->Len(), &cbBytesWritten, FALSE)) {
			SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::Out() failed to write file [%s]"), my_ptr<_TCHAR>(AxLib::APerror()).get());
		}
		m_cbOutPos += pSeg->Len();
		pSeg->Release();
	}

	/// \brief Open the file named in Init() for output
	///
	/// Check for errors with GetErrorCode().
	/// \return true to propagate the open, which we do if no error. false is not an error condition.
	bool
		CSinkFileIO::OutOpen() {
		// If it's there, open for writing, otherwise create it.
		m_hFile = ::CreateFile(m_szFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (m_hFile == INVALID_HANDLE_VALUE) {
			SetError(ERROR_CODE_GENERIC, _T("CSinkFileIO::CSinkFileIO open error [%s]"), my_ptr<_TCHAR>(AxLib::APerror(m_szFileName)).get());
		}
		m_cbOutPos = 0;
		return true;
	}
};