#ifndef	_CFILE
#define	_CFILE
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2020 Svante Seleborg/Axon Data, All rights reserved.

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
	CFile.h							Basic open/read/write/memory map operations on files.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2003-06-23              1.4d1.5 - Remove std file I/O

*/
#include    "../XecretsFileCommon/Types.h"
#include    "CCryptoRand.h"
//
//	Used to keep track and restore all file-times.
//
struct SFileTimes {
	FILETIME CreationTime;
	FILETIME LastAccessTime;
	FILETIME LastWriteTime;
};
//
// Support operations for input and output to (file) streams,
// both through memory maps and some normal IO.
//
// This is also a base-class for some special classes of 'dummy'
// files used for cryptographic wiping, hashing etc.
//
// The reason for virtualness is that the transformer class must
// operate properly regardless of which derived class is used
// in the transformation.
//
class CNoXform;
class CFileIO {
public:
	CFileIO();
	~CFileIO();
	// Open/Create the file with given modes.
	virtual void Open(LPCTSTR szFileName, BOOL fForceWriteThru, DWORD dwReadWrite, DWORD dwShareMode = 0);
	void OpenDir(LPCTSTR szFileName, DWORD dwReadWrite = GENERIC_READ | GENERIC_WRITE, DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE);
	virtual void Create(LPCTSTR szFileName, BOOL fForceWriteThru, DWORD dwReadWrite, DWORD dwOpenMode = CREATE_NEW);
	// Build a temporary file name, and open it. FALSE if fail.
	virtual void MakeTmp(LPCTSTR szFileName, BOOL fForceWriteThru);
	virtual void FlushBuffers();
	virtual void Close(BOOL fForceKeepOnClose = FALSE);
	void ForceClose();                      ///< Catastrophic close, no asserts
	void WipeTemp(HWND hProgressWnd, int nPass = 1);
	void WipeData(HWND hProgressWnd, int nPass = 1);
	void WipeShort(int nPass = 1);	// Just wipe the first 512 bytes of the file.
	virtual void ReadData(void* pBuf, size_t* pcb);
	virtual void WriteData(const void* pBuf, size_t* pcb);
	// Helpers for regular file I/O.
	virtual void SetFilePointer(LONGLONG llPos);
	virtual LONGLONG GetFilePointer();
	virtual LONGLONG GetFileSize();
	virtual void SetEndOfFile();
	virtual void SetFileTimes(SFileTimes* pFileTimes);
	virtual SFileTimes* GetFileTimes();
	virtual LPCTSTR GetFileName();
	LPCTSTR FileName();
	void SetNotCompressed();

	void SetWriteThru(BOOL fForceWriteThru);
	void SetDelete(BOOL fDeleteOnClose);
public:
	QWORD m_qwFileSize;			// This is the maximum known/expected size of the file. It may be 0 to begin with for output files.
protected:
	HANDLE m_hFile;				// The file...
private:
	BOOL CreateEx(LPCTSTR szFileName, DWORD dwReadWrite, DWORD dwOpenMode, DWORD dwShareMode, DWORD dwFlags);
	void Wipe(CNoXform& copier, QWORD qwSize, int nPass);
	void WipeOnePass(CFileIO& fileSrc, CNoXform& copier, QWORD qwSize);
	LPTSTR m_szFileName;		// Remember filename for use with error messages, wipings etc.
	BOOL m_fDeleteOnClose;		// Set to have the Close() also delete the file.
	BOOL m_fIsTmp;
	BOOL m_fForceWriteThru;     // Set when wiping data to ensure that data is physically written to disk.
	SFileTimes m_FileTimes;
	BOOL m_fIsOpenedForWrite;	// Set when a file is opened for writing.
};
/// \brief Handle smart open, where we open as well as we can
class CSmartFileIO : public CFileIO {
	DWORD m_dwReadWrite;                    ///< Keep track of actual open mode
public:
	CSmartFileIO();
	void Open(LPCTSTR szFileName, DWORD dwReadWrite, DWORD dwShareMode = 0);
	bool IsWriteable();                     ///< true if we could open in writeable mode
};
//
//	A placeholder CFileIO class. It will never receive or consume any data,
//	it is only there so that the tranformation class may run.
//
class CFileDummy : public CFileIO {
public:
	CFileDummy() {}
	~CFileDummy() {}
	// Dummy functions - do NOTHING!
	virtual void Open(LPCTSTR szFileName, DWORD dwReadWrite) {}
	virtual void Create(LPCTSTR szFileName, DWORD dwReadWrite) {}
	virtual void MakeTmp(LPCTSTR szFileName) {}
	virtual void Close() {}
	virtual void ReadData(void* pBuf, size_t* pcb) {}
	virtual void WriteData(const void* pBuf, size_t* pcb) {}
	virtual void SetFilePointer(LONGLONG llPos) {}
	virtual LONGLONG GetFilePointer() { return 0; }
	virtual LONGLONG GetFileSize() { return 0; }
	virtual void SetEndOfFile() {}
	virtual void SetFileTimes(SFileTimes* pFileTimes) {}
	virtual SFileTimes* GetFileTimes() { return NULL; }

	virtual LPCTSTR GetFileName() { return NULL; }
};

/// Produce all ones, i.e. 0xff when read
class CFileOne : public CFileDummy {
public:
	virtual void ReadData(void* pBuf, size_t* pcb) { memset(pBuf, 0xff, *pcb); }
};

/// Produce all zeroes, i.e. 0x00 when read
class CFileZero : public CFileDummy {
public:
	virtual void ReadData(void* pBuf, size_t* pcb) { memset(pBuf, 0x00, *pcb); }
};

/// Produce random data when read
class CFileRandom : public CFileDummy {
private:
	CCryptoRand m_utRnd;            // This is where we generate random data from
public:
	// Seed with only internally generated entropy, for what it is worth.
	CFileRandom() { m_utRnd.Seed(NULL, 0); }
	virtual void ReadData(void* pBuf, size_t* pcb) { m_utRnd.RandomFill(pBuf, (DWORD)*pcb); }
};

#endif	_CFILE