/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
	CFile.cpp						Basic open/read/write/memory map operations on files.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2001-11-29				Moved temp-files to the temp dir.
									2002-08-11              Rel 1.2
									2003-06-23              1.4d1.5 - Remove std file I/O

*/
#include	"StdAfx.h"
#include	"../XecretsFileCommon/CFileName.h"
#include	"CFile.h"
#include    "CXform.h"
#include    <winioctl.h>

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CFile.cpp"
//
//	File-operations, the source and destination of a transformation.
//
CFileIO::CFileIO() {
	m_hFile = INVALID_HANDLE_VALUE;
	m_qwFileSize = 0;
	m_szFileName = NULL;
	m_fForceWriteThru = m_fDeleteOnClose = m_fIsTmp = FALSE;
}
//
//	Unmap view, close mapping and close the file itself.
//
CFileIO::~CFileIO() {
	Close();
	if (m_szFileName != NULL) delete m_szFileName;
}
//
//	dwReadWrite would normally be GENERIC_READ or GENERIC_READ|GENERIC_WRITE
//	dwOpenMode would normally be OPEN_EXISTING, CREATE_NEW or CREATE_ALWAYS
//
BOOL
CFileIO::CreateEx(LPCTSTR szFileName, DWORD dwReadWrite, DWORD dwOpenMode, DWORD dwShareMode, DWORD dwFlags) {
	if (m_szFileName != NULL) delete m_szFileName;
	size_t ccFileName = _tcslen(szFileName) + 1;
	m_szFileName = new _TCHAR[ccFileName];
	ASSPTR(m_szFileName);

	_tcscpy_s(m_szFileName, ccFileName, szFileName);
	//
	//  As we sometimes have difficult-to-handle problems with the shell locking
	//  files for us, we simply brute-force for now by insisting if we get a
	//  sharing violation. This seems to be really OS-dependent as well as
	//  situation dependent (it get's worse with network drives for example).
	//  This should really, really, be solved in the Shell Extension once and for
	//  all in a way that makes it always let go of files!!!
	//
	// Retry until success, or the timeout has been reached. This is in milliseconds.
	const DWORD msTimeOut = 1500;
	DWORD msStartTick = GetTickCount();
	DWORD lastError = 0;
	while ((GetTickCount() - msStartTick) < msTimeOut) {
		m_hFile = CreateFile(
			m_szFileName,
			dwReadWrite,
			dwShareMode,
			NULL,
			dwOpenMode,
			dwFlags,
			NULL);
		lastError = GetLastError();
		if (m_hFile != INVALID_HANDLE_VALUE) {
			break;
		}
		else {
			if (lastError != ERROR_SHARING_VIOLATION) {
				break;
			}
		}
		Sleep(20);
	}
	if (m_hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER li;
		li.LowPart = ::GetFileSize(m_hFile, (DWORD*)&li.HighPart);
		CAssert(li.LowPart != 0xFFFFFFFF || GetLastError() == NO_ERROR).File(szFileName).Throw();
		//
		//	We now handle full 64-bit values for filesizes.
		//
		m_qwFileSize = li.QuadPart;
	}
	return m_hFile != INVALID_HANDLE_VALUE;
}
//
//	dwReadWrite would normally be GENERIC_READ or GENERIC_READ|GENERIC_WRITE
//	dwOpenMode would normally be OPEN_EXISTING, CREATE_NEW or CREATE_ALWAYS
//
void
CFileIO::Open(LPCTSTR szFileName, BOOL fForceWriteThru, DWORD dwReadWrite, DWORD dwShareMode) {
	m_fDeleteOnClose = FALSE;
	// Don't optimize with FILE_FLAG_SEQUENTIAL_SCAN, since there are indications WebDrive mis-interprets this. Also, it's not strictly true.
	DWORD dwFlagsAndAttributes = 0;

	m_fIsOpenedForWrite = (dwReadWrite & GENERIC_WRITE) != 0;
	// Seems to reduce problems with removable media. Also is good for safety-first anyway.
	if (m_fIsOpenedForWrite && (true || fForceWriteThru)) {
		SetWriteThru(TRUE);     // Ensure data actually gets flushed from the view
		dwFlagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;
	}
	CAssert(CreateEx(szFileName, dwReadWrite, OPEN_EXISTING, dwShareMode, dwFlagsAndAttributes)).Sys().Throw();
}
//
//  Open directory.
//
void
CFileIO::OpenDir(LPCTSTR szFileName, DWORD dwReadWrite, DWORD dwShareMode) {
	m_fDeleteOnClose = FALSE;
	CAssert(CreateEx(szFileName, dwReadWrite, OPEN_EXISTING, dwShareMode, FILE_FLAG_BACKUP_SEMANTICS)).Sys().Throw();
}

//
//	dwReadWrite would normally be GENERIC_READ or GENERIC_READ|GENERIC_WRITE
//	dwOpenMode would normally be OPEN_EXISTING, CREATE_NEW or CREATE_ALWAYS
//
void
CFileIO::Create(LPCTSTR szFileName, BOOL fForceWriteThru, DWORD dwReadWrite, DWORD dwOpenMode) {
	m_fDeleteOnClose = TRUE;
	// Don't optimize with FILE_FLAG_SEQUENTIAL_SCAN, since there are indications WebDrive mis-interprets this. Also, it's not strictly true.
	DWORD dwFlagsAndAttributes = 0;

	m_fIsOpenedForWrite = (dwReadWrite & GENERIC_WRITE) != 0;
	// Seems to reduce problems with removable media. Also is good for safety-first anyway.
	if (m_fIsOpenedForWrite && (true || fForceWriteThru)) {
		SetWriteThru(TRUE);     // Ensure data actually gets flushed from the view
		dwFlagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;
	}
	CAssert(CreateEx(szFileName, dwReadWrite, dwOpenMode, 0, dwFlagsAndAttributes)).Sys().Throw();
}
//
//	Create a writeable temp-file. Throw an TAssert exception on error.
//
void
CFileIO::MakeTmp(LPCTSTR szTempFile, BOOL fForceWriteThru) {
	if (m_szFileName != NULL) delete m_szFileName;
	size_t ccFileName = _tcslen(szTempFile) + 1;
	m_szFileName = new _TCHAR[ccFileName];
	ASSPTR(m_szFileName);

	_tcscpy_s(m_szFileName, ccFileName, szTempFile);

	DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_TEMPORARY |
		FILE_ATTRIBUTE_HIDDEN |
		FILE_FLAG_RANDOM_ACCESS |
		FILE_FLAG_DELETE_ON_CLOSE;
	// Always write through - slower, but safer.
	if (true || fForceWriteThru) {
		SetWriteThru(TRUE);     // Ensure data actually gets flushed from the view
		dwFlagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;
	}
	m_hFile = CreateFile(
		m_szFileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		dwFlagsAndAttributes,
		NULL);
	CAssert(m_hFile != INVALID_HANDLE_VALUE).File(MSG_MAKE_TMP, m_szFileName).Throw();
	m_fIsTmp = TRUE;
	m_fDeleteOnClose = FALSE;			// Actually yes, but this the system handles.
}
//
//  Flush regular file buffers.
//
void
CFileIO::FlushBuffers() {
	if (m_hFile != INVALID_HANDLE_VALUE) {
		// FlushFileBuffers() will fail with Access Denied on Vista x64 for example if the file is opened for reading only.
		if (m_fIsOpenedForWrite) {
			CAssert(FlushFileBuffers(m_hFile)).Sys().Throw();
		}
	}
}
//
//	If the handle is open, close it
//
void
CFileIO::Close(BOOL fForceKeepOnClose) {
	if (m_hFile != INVALID_HANDLE_VALUE) {
		// For absolute safety-first - flush the buffers, even though we're also running in write-through mode
		// and even when we'll be deleting it directly.
		FlushBuffers();
		CAssert(CloseHandle(m_hFile)).Sys().Throw();
		if (m_fDeleteOnClose && !fForceKeepOnClose) {
			CAssert(DeleteFile(m_szFileName)).Sys().Throw();
		}
	}
	m_hFile = INVALID_HANDLE_VALUE;
	m_fForceWriteThru = m_fDeleteOnClose = m_fIsTmp = FALSE;
}

/// \brief Catastrophic close, no asserts
void
CFileIO::ForceClose() {
	FlushBuffers();
	if (m_hFile != INVALID_HANDLE_VALUE) {
		(void)CloseHandle(m_hFile);
		if (m_fDeleteOnClose) {
			(void)DeleteFile(m_szFileName);
		}
		m_hFile = INVALID_HANDLE_VALUE;
	}
	m_qwFileSize = 0;
	if (m_szFileName) {
		delete m_szFileName;
		m_szFileName = NULL;
	}
	m_fForceWriteThru = m_fDeleteOnClose = m_fIsTmp = FALSE;
}
//
//	Wipe this file, and mark it for deletion on close
//
void
CFileIO::WipeTemp(HWND hProgressWnd, int nPass) {
	Wipe(CWipeXform(hProgressWnd, INF_OPNAME_WIPETEMP, nPass), m_qwFileSize, nPass);
}
//
//	Wipe this file, and mark it for deletion on close
//
void
CFileIO::WipeData(HWND hProgressWnd, int nPass) {
	Wipe(CWipeXform(hProgressWnd, INF_OPNAME_WIPEDATA, nPass), m_qwFileSize, nPass);
}
//
//	Just wipe the first 1024 bytes, or less, of the file.
//
void
CFileIO::WipeShort(int nPass) {
	Wipe(CWipeXform(NULL, 0, nPass), Min(m_qwFileSize, 1024), nPass);
}

void
CFileIO::Wipe(CNoXform& copier, QWORD qwSize, int nPass) {
	// Just a placeholder for the transformer logic used by the wiper.
	CFileZero utFileZero;
	CFileOne utFileOne;
	CFileRandom utFileRandom;

	SetWriteThru(TRUE);
	switch (nPass) {
	default:
	case 7:
		WipeOnePass(utFileRandom, copier, qwSize);
		// fall through
	case 6:
		WipeOnePass(utFileOne, copier, qwSize);
		// fall through
	case 5:
		WipeOnePass(utFileZero, copier, qwSize);
		// fall through
	case 4:
		WipeOnePass(utFileRandom, copier, qwSize);
		// fall through
	case 3: // 0x00 + 0xff + random
		WipeOnePass(utFileZero, copier, qwSize);
		// fall through
	case 2: // 0xff + random
		WipeOnePass(utFileOne, copier, qwSize);
		// fall through
	case 1: // Standard random for the non-paranoid
	case 0: // We default to this as well.
		WipeOnePass(utFileRandom, copier, qwSize);
	}
	if (!m_fIsTmp) m_fDeleteOnClose = TRUE;
}

void
CFileIO::WipeOnePass(CFileIO& fileSrc, CNoXform& copier, QWORD qwSize) {
	fileSrc.m_qwFileSize = qwSize;
	fileSrc.SetFilePointer(0);

	SetFilePointer(0);
	copier.XformData(fileSrc, *this);
	FlushBuffers();
}

//
//  Read data sequentially
//
void
CFileIO::ReadData(void* pBuf, size_t* pcb) {
	DWORD dwRead = 0;
	CAssert(ReadFile(m_hFile, pBuf, *pcb, &dwRead, NULL)).Sys().Throw();
	*pcb = dwRead;
}

//
//  Write data sequentially
//
void
CFileIO::WriteData(const void* pBuf, size_t* pcb) {
	DWORD dwWritten = 0;
	CAssert(WriteFile(m_hFile, pBuf, *pcb, &dwWritten, NULL)).Sys().Throw();
	*pcb = dwWritten;
}
//
//	SetFilePointer-wrapper
//
void
CFileIO::SetFilePointer(LONGLONG llPos) {
	CAssert(::SetFilePointer(m_hFile, (DWORD)llPos, &((PLARGE_INTEGER)&llPos)->HighPart, FILE_BEGIN) != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR).Sys().Throw();
}

// Get the current file pointer
LONGLONG CFileIO::GetFilePointer() {
	LARGE_INTEGER liPos;
	liPos.QuadPart = 0;
	liPos.LowPart = ::SetFilePointer(m_hFile, liPos.LowPart, &liPos.HighPart, FILE_CURRENT);
	CAssert(liPos.LowPart != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR).Sys().Throw();
	return liPos.QuadPart;
}

/// GetFileSize
LONGLONG
CFileIO::GetFileSize() {
	LARGE_INTEGER liSize;

	liSize.LowPart = ::GetFileSize(m_hFile, (LPDWORD)&liSize.HighPart);
	CAssert(liSize.LowPart != INVALID_FILE_SIZE || GetLastError() == NO_ERROR).Sys().Throw();
	return liSize.QuadPart;
}
//
//	SetEndOfFile-wrapper
//
void
CFileIO::SetEndOfFile() {
	CAssert(::SetEndOfFile(m_hFile)).Sys().Throw();
}
//
//
void
CFileIO::SetFileTimes(SFileTimes* pFileTimes) {
	CAssert(::SetFileTime(
		m_hFile,
		&pFileTimes->CreationTime,
		&pFileTimes->LastAccessTime,
		&pFileTimes->LastWriteTime)).Sys().Throw();
}

SFileTimes*
CFileIO::GetFileTimes() {
	CAssert(::GetFileTime(
		m_hFile,
		&m_FileTimes.CreationTime,
		&m_FileTimes.LastAccessTime,
		&m_FileTimes.LastWriteTime)).Sys().Throw();
	return &m_FileTimes;
}
//
//	Return the file-name of the associated file.
//
LPCTSTR
CFileIO::FileName() {
	return m_szFileName;
}

LPCTSTR
CFileIO::GetFileName() {
	return m_szFileName;
}
//
//  Set the file or directory compression and encryption state to 'off'.
//
//  This is primarily intended for temp directories, where we want to
//  ensure that they are wipeable.
//
void
CFileIO::SetNotCompressed() {
	USHORT usFormat;
	DWORD dwBytesRet;

	// We fail silently here, as the attribute is not supported on Win95
	if (DeviceIoControl(m_hFile, FSCTL_GET_COMPRESSION, NULL, 0, &usFormat, sizeof usFormat, &dwBytesRet, NULL)) {
		// If the directory or file is compressed, let's change it.
		if (usFormat != COMPRESSION_FORMAT_NONE) {
			usFormat = COMPRESSION_FORMAT_NONE;
			CAssert(DeviceIoControl(m_hFile, FSCTL_SET_COMPRESSION, &usFormat, sizeof usFormat, NULL, 0, &dwBytesRet, NULL)).Sys(MSG_SYSTEM_CALL, _T("CTempDir::New() [DeviceIoControl(FSCTL_SET_COMPRESSION)]")).Throw();
		}
	}
}
//
//  Modify the state of the Write Thru flag, to make some optimizations possible.
//  It should still be set to true on open or create etc, to ensure that the file
//  is opened with the proper file flag.
//
void
CFileIO::SetWriteThru(BOOL fForceWriteThru) {
	m_fForceWriteThru = fForceWriteThru;
}

void
CFileIO::SetDelete(BOOL fDeleteOnClose) {
	m_fDeleteOnClose = fDeleteOnClose;
}

CSmartFileIO::CSmartFileIO() {
	m_dwReadWrite = 0;
}

/// Open a file as well as we can.
/// If RW fails, we try RO instead. We always maintain that we want
/// the sharing mode the caller asks for.
///
/// The point is that there are many reasons why we might not get write
/// access: read-only attribute, write-protection, lacking permissions,
/// sharing violations and perhaps other reasons.
///
void
CSmartFileIO::Open(LPCTSTR szFileName, DWORD dwReadWrite, DWORD dwShareMode) {
	m_dwReadWrite = dwReadWrite;
	if (m_dwReadWrite & GENERIC_WRITE) {
		try {
			CFileIO::Open(szFileName, TRUE, m_dwReadWrite, dwShareMode);
			return;
		}
		catch (TAssert assException) {
			// We catch all exceptions, and just try without write.
			m_dwReadWrite &= ~GENERIC_WRITE;
		}
	}
	CFileIO::Open(szFileName, TRUE, m_dwReadWrite, dwShareMode);
}

/// Check if an opened file is writeable.
bool CSmartFileIO::IsWriteable() {
	return (m_dwReadWrite & GENERIC_WRITE) != 0;
}