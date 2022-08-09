#ifndef _CHEADER_H
#define _CHEADER_H
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
	CHeader.h                       Define format and operations on the headers in the wrapped
									output file.

	E-mail                          YYYY-MM-DD              Reason
	software@axantum.com             2001                    Initial
									2002-08-06              Rel 1.2
									2003-06-23              1.4d1.5 - Remove std file I/O

*/
#include    "../XecretsFileCommon/CAes.h"
#include    "CFile.h"
#include    "../XecretsFileCommon/CFileName.h"
#include    "../XecretsFileCommon/CAssert.h"
//
// Ensure the correct and expected structures regardless of optimizations.
//
#pragma pack(push)
#pragma pack(1)
//
//  The different header types. Preamble must be first, Data last.
//  Sections with eEncryptedFlag set will be encrypted with variations
//  of the Initialization Vector and the Data Encrypting Key
//
//  The presence of a specific type of Key Wrap-Header fully defines
//  both the fact of encryption, and also what encryption and key is used.
//
//  Obviously a non-encrypted file would not encrypt the headers that may
//  be encrypted (after eEncryptedFlag that is).
//
typedef enum {
	eAny = 1,                           // Matches any type. Do not want to use Zero

	ePreamble,                          // Must be first.
	eVersion,                           // Version information etc.
	eKeyWrap1,                          // A 128-bit Data Enc Key and IV wrapped with 128-bit KEK
	eKeyWrap2,                          // Some other kind of KEK, DEK, IV scheme... Future use.
	eIdTag,                             // An arbitrary string defined by the caller.
	eData = 63,                         // The data, compressed and/or encrypted.
	eEncryptedFlag = 64,                // Start of headers containing encrypted header data
	eFileNameInfo,                      // Original file name
	eEncryptionInfo,                    // Sizes of the original data file before encryption
	eCompressionInfo,                   // Indicates that the data is compressed and the sizes.
	eFileInfo,                          // Time stamps and size of the original file
	eCompressionFlag,                   // Indicates if the data is compressed. 1.2.2.
	eUnicodeFileNameInfo,               // Original file name in Unicode. 1.6.3.3
} TBlockType;
//
class CHeaders;                         // Forward for friend declarations

// helper for fault tolerance/data recovery
extern void ConditionalThrow(TAssert& utErr, DWORD dwMsgId);

//
//  This is a base class not indended for instantiation, although it is not pure.
//
//  The purpose is to package all the common parts of a header in the wrapped file,
//  notable the total header/section length and it's type.
//
class CHeaderHeader {
	friend CHeaders;
public:
	CHeaderHeader();
	virtual ~CHeaderHeader();
	void SetType(TBlockType eType);     // Mark the block with a type
	void PutAll(CFileIO& rFile);        // Write this and all following headers to the file.
	DWORD Size();                       // Size of this header only
	DWORD SizeAll();                    // Size of this and following headers
	static TBlockType PeekType(CFileIO& rFile);
	TBlockType GetType() { return (TBlockType)m_utHeader.oType; }
	void Get(CFileIO& rFile);           // Load header data from file
protected:
	void Put(CFileIO& rFile);           // Write header data to the file.

	// Endian-independent load/store DWORD
	static void SetDW(BYTE aoValue[4], DWORD dwValue);
	static DWORD GetDW(BYTE aoValue[4]);
	// Endian-independent load/store QWORD
	static void SetQW(BYTE aoDst[8], QWORD qwValue);
	static QWORD GetQW(BYTE aoSrc[8]);
	// All SHeader structures must consist of bytes or arrays of bytes that are
	// not sensitive to byte ordering issues, as they are read and written
	// directly to the file as an entire structure.
	struct SHeader {
		BYTE aoLength[4];               // Total length of header section
		BYTE oType;                     // Cast to TBlockType as appropriate.
	} m_utHeader;
private:
	class CHeaderHeader* m_pNext;       // Next.
protected:
	//  This is to implement a 'virtual' continuation header in the derived classes.
	//  The constructors there will fill this data.
	void AllocateHeader(size_t iLen, size_t iAlign);  // Allocate and round
	DWORD m_iHeaderSize;                // Total, in memory length of 'real' header
	void* m_pvHeaderData;               // The 'real' header
};
//
//  ePreamble - This must come first in the file
//
class CHeaderPreamble : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderPreamble();                  // Init size and type
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	struct SPreamble {
		THmac utHMAC;                   // HMAC-SHA1-128 of header and data excl. preamble.
	};
};
//
// eVersion - included in the hash, checked after we have checked file integrity to protect against
// possible hacking by changing version info.
//
class CHeaderVersion : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderVersion();
	void Set();                         // Init all the fine constants representing the versions
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	struct SVersion {
		BYTE oFileVersionMajor;         // FileMajor - Older versions cannot not read the format.
		BYTE oFileVersionMinor;         // FileMinor - Older versions can read the format, but will not retain on save.
		BYTE oVersionMajor;             // Major - New release, major functionality change.
		BYTE oVersionMinor;             // Minor - Changes, but no big deal.
		BYTE oVersionMinuscle;          // Minuscle - bugfix.
	};
};
//
//  The Data Encrypting Key, along with the IV is wrapped according to FIPS recommendation.
//
//  The Key Wrap algorithm also supplies integrity check, so we know if the correct
//  Key Encrypting Key is given.
//
//  eKeyWrap1
//
class CHeaderKeyWrap1 : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderKeyWrap1();
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	struct SKeyWrap {
		BYTE utKeyData[1 + sizeof TKey / 8][8];         // The Key Data (A + DEK).
		BYTE oSalt[16];                 // Salt, xor'ed with KEK before wrap/unwrap.
		BYTE oIter[4];                  // Custom number of iterations for work factor increase
	};
};
//
//  The original file name
//
//  eFileNameInfo
//
class CHeaderFileNameInfo : public CHeaderHeader {
public:
	CHeaderFileNameInfo();
private:
	struct SFileNameInfo {
		// TCHAR szFileName[*];         // Buffer for file-name.
	};
};

//
//  The original file name in Unicode
//
//  eUnicodeFileNameInfo
//
class CHeaderUnicodeFileNameInfo : public CHeaderHeader {
public:
	CHeaderUnicodeFileNameInfo();
private:
	struct SUnicodeFileNameInfo {
		// wchar_t wzFileName[*];         // Buffer for file-name.
	};
};

//
//  Data about the compression transform of the file. This is
//  an optional header - if it is not there - no compression.
//
class CHeaderCompressionInfo : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderCompressionInfo();
private:
	// Actual storage in the base class
	struct SCompressionInfo {
		BYTE aoNormalSize[8];       // The size of the uncompressed data
	};
};
//
//  A flag indicating if compression was used, or not. The flag is
//  always there, thus hiding the fact of compression or not.
//
class CHeaderCompressionFlag : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderCompressionFlag();
private:
	// Actual storage in the base class
	struct SCompressionFlag {
		BYTE aoCompFlag[sizeof DWORD];      // TRUE if compression was used.
	};
};
//
//  Data about the encryption transform of the file.
//
class CHeaderEncryptionInfo : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderEncryptionInfo();
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	// must be a TBlock multiple length. Assured by constructor code
	struct SEncryptionInfo {
		BYTE aoPlainSize[8];        // The size of the plain text (still possibly compressed!)
		TBlock utIV;                // The IV used for CBC encryption.
	};
};
//
//  File times and size of the original file
//
class CHeaderFileInfo : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderFileInfo();
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	// must be a TBlock multiple length. Assured by constructor code
	struct SFileInfo {
		BYTE aoFileTimes[sizeof SFileTimes];
	};
};

//
//  The actual file data is stored as one contiguous block directly
//  following, but not really a part of, this last header.
//
//  eData
//
class CHeaderData : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderData();                  // Init with type and zero data length.
private:
	// Actual storage in the base class - NOTE it is just a structure definition...
	struct SData {
		BYTE aoDataSize[8];         // The size of the possibly padded/encrypted/compressed data
	};
};
//
// IdTag, stored in ACP.
//
class CHeaderIdTag : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderIdTag();
private:
	// Actual storage in the base class!
	struct SIdTag {
		// char szIdTag[*]; // Yes, char, not TCHAR or WCHAR.
	};
};
//
//  Dummy class to instantiate and skip unknown headers
//
class CHeaderUnknown : public CHeaderHeader {
	friend CHeaders;
public:
	CHeaderUnknown() : CHeaderHeader() {}
};
//
//  Container class for a header set.
//
//  Externally we know and depend on Preamble being first, and Data last.
//
//
class CHeaders {
public:
	CHeaders();
	~CHeaders();
	//
	THmac* GetHMAC();
	void SetHMAC(THmac* pHMAC);

	BYTE GetFileVersionMajor();
	BYTE GetFileVersionMinor();
	void SetFileVersion();              // Actual version is generated internally.

	void SetIV();                       // Generated internally
	TBlock* GetIV();

	TKey* GetDataEncKey();              // Throw error if not set.
	void SetDataEncKey(TKey* pKeyEncKey);
	//  void AddKeyEncKey(TKey *pNewKeyEncKey, TKey *pKeyEncKey);   // Add another, but must know one!

	void SetPlainSize(QWORD qwReal);    // Store the length of the plaintext in the header
	QWORD GetPlainSize();               // Get the length of the plaintext in the header

	void SetNormalSize(QWORD dwCompressed); // Store the length of the compressed plaintext in the header
	QWORD GetNormalSize();              // Get the length of the compressed plaintext from the header in memory
	BOOL IsCompressed();                // TRUE if headers include a compression header.
	void SetCompressionFlag(BOOL fCompFlag); // Indicate if compression is used, or not.

	void SetDataSize(QWORD dwEncrypted);
	QWORD GetDataSize();

	void SetFileTimes(SFileTimes* pFileTime);   // Store the time the plain text was last written to.
	SFileTimes* GetFileTimes();         // Get the tiem the plain text was last written to.
	int CompareFileTime(FILETIME* pLastWriteTime);

	LPTSTR GetFileName();            // Get original file name
	void SetFileName(LPCTSTR szFileName);// Set the original name of the file.

	void SetIdTag(const TCHAR* szIdTag);// Set an IdTag
	TCHAR* GetIdTag();                  // Get an IdTag

	DWORD OffsetToHMAC();               // Where to start HMAC'ing
//
	CHeaders& Load(CFileIO& rFile);     // Load from file - verify GUID & Header structure
	BOOL Open(TKey* pKeyEncKey);        // Verify correct key, and decrypt etc.
	BOOL ReOpen();                      // Re-open using existing valid key.
	void WrapKeyData(TKey* pKeyEncKey); // Wrap the data-encrypting key.
	void Close();                       // Encrypt headers etc.
	void Save(CFileIO& rFile, HWND hProgressWnd, LONGLONG llOffset = 0); // Write them to the file
	CHeaders& Init();                   // Init with all new structures - is also open!
	CHeaders& Clear();                  // Clear all data.
	DWORD SizeInMemory();               // Total size of headers in memory.
	DWORD SizeOnFile();                 // Total size of the headers read from file.

	void VerifyStructure(CFileIO& rFile);   // Scan the file and verify it's structure.
private:

	void EncryptHeaders();              // Encrypt headers
	void DecryptHeaders();              // Decrypt headers
	void EncDecHelper(CAes::etDirection eDirection);

	BOOL UnAESWrapKey(TKey* pKeyEncKey, CHeaderKeyWrap1* pKeyWrap); // Attempt to unwrap
	void AESWrapKey(TKey* pKeyEncKey, CHeaderKeyWrap1* pKeyWrap);   // Wrap key and IV with KEK

	CHeaderHeader* Find(TBlockType eType);  // Null if not found.
	CHeaderHeader* Add(void* pNewHeader);   // CAssert if error
	void Remove(void* pHeader);    // Remove a header from the chain.
//
	CHeaderHeader* m_pFirst;            // First in chain.
	TKey* m_pDataEncKey;                // The ready-to-use key from Set...() or Open()
	TBlock* m_pIV;                      // The ready-to-use IV
	BOOL m_fKeyIsValid;
	BOOL m_fOpen;                       // TRUE when headers are in decrypted state.
	SFileTimes m_utFileTimes;           // Buffer for FileTime queries.
	LPTSTR m_szFileName;                // The original (plaintext) file name.
	CFileName m_EncryptedFileName;      // The ciphertext file name.
	DWORD m_dwSizeOnFile;               // The total size of the headers read from file.
};
#pragma pack(pop)
#endif  _CHEADER_H