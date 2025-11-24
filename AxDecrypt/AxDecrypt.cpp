/*! \file
	\brief AxDecrypt - Stand-alone Xecrets File Classic-decrypter and self-extractor.

	@(#) $Id$
*/
/*! \page License AxDecrypt - Stand-alone Xecrets File Classic-decrypter and self-extractor.

	Copyright (C) 2004-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
*/
//    version
//    htmlinclude Version.txt
/*! \mainpage Decrypt Xecrets File Classic-archives as a stand-alone program.

	\author
	Svante Seleborg/Axon Data

	\par License:
	\ref License "GNU General Public License"

	Security design-goals: None, really. Just decrypt and leave the plain-text
	in a place of the users choice. No attempts are made to keep passphrases out
	of memory, swap-files etc. Use this program only on a trusted system!

	The design relies heavily on the <A HREF=http://axpipe.sourceforge.net>AxPipe</A> binary stream implementation.

	There is a GUI-aware part that presents the main window etc.
	There is a non-GUI-aware part that does all the work, consisting of a number
	of AxPipe-style pipe sections doing things like skipping to the first
	file, parsing headers, check for cancel, decrypting, inflating, setting
	file times etc.
	There is also an intermediary between the GUI-aware and the non-aware parts,
	called CAxDecryptBase which is an abstract base class, with it's derivation
	CAxDecryptSelf which contains the specific code for this GUI.

	The program starts as usual in ::WinMain(), and the real work get's done when
	CAxDecryptSelf::Work is called.
*/
#include "stdafx.h"

// Use the wrapper for GetLongPathName() to support pre sp 3 NT4. [BUG 993963]
// 2008-01-17 W no longer support Windows NT
//#define WANT_GETLONGPATHNAME_WRAPPER        ///< Make GetLongPathName() exist on Win NT pre sp 3 (and 95)
//#define COMPILE_NEWAPIS_STUBS               ///< Make NewAPIs.h actually include the code too
//#pragma push_macro("BOOL")                  // Save the current value of BOOL
//#define BOOL DWORD                          ///< Bug in NewAPIs.h, causing C2440 - this is an ugly fix.
//#include <NewAPIs.h>
//#pragma pop_macro("BOOL")                   // Restore BOOL (actually undefined, is a typedef, but for consistency...)

/// \brief Tell initguid.h that we want to actually define a guid here.
///
/// This is to actually define the GUID in XecretsFileGUID.h.
/// We now know that we'll find the XecretsFileGUID first inside
/// our-selves, and then, if it exists in the appended archive(s).
#define	INITGUID
#include <initguid.h>

/// \brief The Xecrets File GUID
///
/// Define the guid here xor 0xff, i.e. inverted, so we won't trig on it
/// when scanning for GUID in ourselves, looking for the appended .xxx-
/// files.
DEFINE_GUID(guidAxCryptFileIdInverse,
	0x2e07b9c0 ^ 0xffffffff,
	0x934f ^ 0xffff,
	0x46f1 ^ 0xffff,
	0xa0 ^ 0xff, 0x15 ^ 0xff, 0x79 ^ 0xff, 0x2c ^ 0xff, 0xa1 ^ 0xff, 0xd9 ^ 0xff, 0xe8 ^ 0xff, 0x21 ^ 0xff
);

#ifdef _DEBUG
const int mChunkSize = 0x101;               ///< The chunk size we work in.
#else
const int mChunkSize = 0x100000;            ///< The chunk size we work in.
#endif

/// \brief Custom error codes from ::AxPipe -derived classes.
enum {
	ERROR_CODE_XECRETSFILE = AxPipe::ERROR_CODE_DERIVED, ///< Generic custom error
	ERROR_CODE_CANCEL,                      ///< User cancelled in a dialog box before start
	ERROR_CODE_HMAC,                        ///< HMAC does not match
	ERROR_CODE_ABORT,                       ///< User cancelled whilst working
	ERROR_CODE_MORE,                        ///< Not an error - want a bigger dialog
	XECRETSFILE_CODE_DATA,                      ///< Not an error - we found Xecrets File Classic data status
};

/// \brief Xecrets File Classic Header Type Codes.
///
/// The different header types. Preamble must be first, Data last.
/// Sections with eEncryptedFlag set will be encrypted with variations
/// of the Initialization Vector and the Data Encrypting Key
///
/// The presence of a specific type of Key Wrap-Header fully defines
/// both the fact of encryption, and also what encryption and key is used.
///
/// Obviously a non-encrypted file would not encrypt the headers that may
/// be encrypted (after eEncryptedFlag that is).
typedef enum {
	eNone = 0,                          ///< Matches no type.
	eAny = 1,                           ///< Matches any type.

	ePreamble,                          ///< Must be first.
	eVersion,                           ///< Version information etc.
	eKeyWrap1,                          ///< A 128-bit Data Enc Key and IV wrapped with 128-bit KEK
	eKeyWrap2,                          ///< Some other kind of KEK, DEK, IV scheme... Future use.
	eIdTag,                             ///< An arbitrary string defined by the caller.
	eData = 63,                         ///< The data, compressed and/or encrypted.
	eEncryptedFlag = 64,                ///< Start of headers containing encrypted header data
	eFileNameInfo,                      ///< Original file name
	eEncryptionInfo,                    ///< Sizes of the original data file before encryption
	eCompressionInfo,                   ///< Indicates that the data is compressed and the sizes.
	eFileInfo,                          ///< Time stamps and size of the original file
	eCompressionFlag,                   ///< Indicates if the data is compressed. 1.2.2.
	eUnicodeFileNameInfo,               ///< Original file name in Unicode. 1.6.3.3
} TBlockType;

/// \brief Get version from version resources
///
/// Get various version info from version resources of an
/// executable, perhaps ourselves.
class CVersion {
	VS_FIXEDFILEINFO* m_pFixedFileInfo;     ///< Fixed info, references m_pFileVersionInfo
	void* m_pFileVersionInfo;               ///< The version resources from the executable
public:
	CVersion(HINSTANCE hInstance = NULL);   ///< Load the resources
	~CVersion();                            ///< Free allocated memory
	BYTE Major();                           ///< Get the Major version byte
	BYTE Minor();                           ///< Get the Minor version byte
	WORD Minuscle();                        ///< Get the Minuscle version byte
	WORD Patch();                           ///< Get the Patch level version byte
	_TCHAR* newProductName();               ///< Product name, from resource. Allocated.
	_TCHAR* newCompanyName();               ///< Company name, from resource. Allocated.
	_TCHAR* newLegalCopyright();            ///< Copyright string, from resource. Allocated.
	_TCHAR* newNameVersionString(UINT uProductName = 0);         ///< Formatted version string. Allocated.
};

/// \brief Initalize and load the actual version resources
///
/// Get the version resources
/// from an executable. Will assert and exit on error.
/// \param hInstance The module with the resources. NULL means ourselves.
CVersion::CVersion(HINSTANCE hInstance) {
	m_pFileVersionInfo = NULL;

	// Get the version resource from the executable identified by the instance
	TCHAR szFileName[_MAX_PATH];
	ASSAPI(GetModuleFileName(hInstance, szFileName, sizeof szFileName) != 0);

	DWORD dwDummy, dwLen = GetFileVersionInfoSize(szFileName, &dwDummy);
	ASSAPI(dwLen != 0);
	m_pFileVersionInfo = new BYTE[dwLen];
	ASSPTR(m_pFileVersionInfo);

	ASSAPI(GetFileVersionInfo(szFileName, dwDummy, dwLen, m_pFileVersionInfo) == TRUE);
	UINT uLen = 0;
	ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\"), (void**)&m_pFixedFileInfo, &uLen) == TRUE);
}

/// \brief Clean up and free memory.
CVersion::~CVersion() {
	delete m_pFileVersionInfo;
}

/// \brief Get the Major byte of the version number, i.e. X.n.n.n
/// \return A number 0-255
BYTE
CVersion::Major() {
	return (BYTE)(m_pFixedFileInfo->dwProductVersionMS >> 16);
}

/// \brief Get the Minor byte of the version number, i.e. n.X.n.n
/// \return A number 0-255
BYTE
CVersion::Minor() {
	return (BYTE)(m_pFixedFileInfo->dwProductVersionMS);
}

/// \brief Get the Minuscle byte of the version number, n.n.X.n
/// \return A number 0-255
WORD
CVersion::Minuscle() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionLS >> 16);
}

/// \brief Get the Patch level byte of the version number, i.e. n.n.n.X
/// \return A number 0-255
WORD
CVersion::Patch() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionLS);
}

/// \brief Get the Product Name, taken from the resouces.
/// \return An allocated string, must be delete'd.
_TCHAR*
CVersion::newProductName() {
	UINT uLen = 0;
	_TCHAR* szProductName = NULL;
	ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\ProductName"), (void**)&szProductName, &uLen) == TRUE);
	ASSCHK(szProductName && uLen != 0, _T(""));

	return lstrcpyn(new _TCHAR[uLen], szProductName, uLen);
}

/// \brief Get the Company name from the resources.
/// \return An allocated string, must be delete'd.
_TCHAR*
CVersion::newCompanyName() {
	UINT uLen = 0;
	_TCHAR* szCompanyName = NULL;
	ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\CompanyName"), (void**)&szCompanyName, &uLen) == TRUE);
	ASSCHK(szCompanyName && uLen != 0, _T(""));

	return lstrcpyn(new _TCHAR[uLen], szCompanyName, uLen);
}

/// \brief Copyright string, from resource.
/// \return An allocated string, must be delete'd.
_TCHAR*
CVersion::newLegalCopyright() {
	UINT uLen = 0;
	_TCHAR* szLegalCopyright = NULL;
	ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\LegalCopyright"), (void**)&szLegalCopyright, &uLen) == TRUE);
	ASSCHK(szLegalCopyright && uLen != 0, _T(""));

	return lstrcpyn(new _TCHAR[uLen], szLegalCopyright, uLen);
}

/// \brief Format a version string, including the product name, and possible a special build insert.
/// \param szAltProductName Alternate product to use instead of resource-embedded.
/// \return An allocated string, must be delete'd.
_TCHAR*
CVersion::newNameVersionString(UINT uProductName) {
	// Get special build field
	UINT uLen = 0;
	LPCTSTR szSpecialBuild = _T("");
	// It's not actually an error not to find this resource, VC7 doesn't included it if it's empty...
	VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\SpecialBuild"), (void**)&szSpecialBuild, &uLen);

	_TCHAR* szProductName;
	if (uProductName != 0) {
		szProductName = ALoadString(uProductName);
	}
	else {
		szProductName = newProductName();
	}
	_TCHAR* szVersionString = new _TCHAR[1024];
	if (szSpecialBuild && uLen) {
		wsprintf(szVersionString, Patch() ? _T("%s %d.%d.%d.%d %s") : _T("%s %d.%d.%d.%d %s"), szProductName, Major(), Minor(), Minuscle(), Patch(), szSpecialBuild);
	}
	else {
		wsprintf(szVersionString, Patch() ? _T("%s %d.%d.%d.%d") : _T("%s %d.%d.%d.%d"), szProductName, Major(), Minor(), Minuscle(), Patch());
	}
	delete szProductName;

	return szVersionString;
}

/// \brief Check if anything is passed.
///
/// The sink works as a /dev/nul, but will signal
/// a sucess code with SetError if any data is actually
/// sent there.
class CSinkCheckAny : public CSink {
protected:
	/// \brief If we get data, we set the error code XECRETSFILE_CODE_DATA, and drop the segment.
	void Out(CSeg* pSeg) {
		SetError(XECRETSFILE_CODE_DATA, _T(""));
		pSeg->Release();
	}
};

/// \brief Exactly one meta section from an Xecrets File Classic-formated file stream.
class CMetaSection {
	TBlockType m_eType;                     ///< The type of the section, defined by TBlockType
	size_t m_cbLen;                         ///< The total length of m_pData (excluding type byte)
	void* m_pData;                          ///< The raw data, excluding type byte

	/// \brief Assignment by copying of compontens making up a section
	/// \param eType The section type
	/// \param pData Pointer to the data block of the section
	/// \param cbLen The length of pData
	void CopyAssign(TBlockType eType, void* pData, size_t cbLen) {
		m_eType = eType;
		m_cbLen = cbLen;
		if (m_cbLen && pData) {
			ASSPTR(m_pData = new unsigned char[m_cbLen]);
			memcpy(m_pData, pData, m_cbLen);
		}
		else {
			m_pData = NULL;
		}
	}
public:
	/// \brief Take ownership of the buffer when constructed like this.
	///
	/// This also serves as the default constructor by way of default values
	/// for parameters.
	/// \param eType The section type (not the Swedish music artist ;-)
	/// \param pData Pointer to the data block of the section
	/// \param cbLen The length of pData
	CMetaSection(TBlockType eType = eNone, void* pData = NULL, size_t cbLen = 0) {
		m_eType = eType;
		m_pData = pData;
		m_cbLen = cbLen;
	}

	/// \brief A proper copy-constructor
	/// \see CopyAssign
	CMetaSection(const CMetaSection& rhs) {
		CopyAssign(rhs.m_eType, rhs.m_pData, rhs.m_cbLen);
	}

	/// \brief delete the data buffer
	~CMetaSection() {
		delete m_pData;
	}

	/// \brief Assign-by-copy
	/// \return A reference to *this
	CMetaSection& operator=(const CMetaSection& rhs) {
		CopyAssign(rhs.m_eType, rhs.m_pData, rhs.m_cbLen);
		return *this;
	}

	/// \brief Get the TBlockType type of the section
	/// \return The type
	TBlockType Type() {
		return m_eType;
	}

	/// \brief Get the length of data excluding type
	/// \return The length in bytes
	size_t Len() {
		return m_cbLen;
	}

	/// \brief Get a pointer to the data buffer
	/// \return The pointer
	void* Data() {
		return m_pData;
	}
};

/// \brief Send both a string and contents of a file downstream
/// First send the contents of a 'char' string, then the contents
/// of a file (if there is any).
class CAxCryptKeySeq : public AxPipe::CSourceFileIO {
	auto_ptr<char> m_szPassphrase;          ///< The passphrase to start sending
	bool m_fHaveFile;                       ///< true if we got a file name to send too

public:
	/// \brief Initialize private members.
	CAxCryptKeySeq() : m_szPassphrase(NULL), m_fHaveFile(false) {}

	/// \brief Store a copy of the passphrase, and init the file source if any
	/// \param szPassphrase A char string
	/// \param szKeyFileName The name of a file to also pass data from (after the string)
	/// \param cbChunk The size of the chunks to work with
	/// \return A pointer to 'this'
	CAxCryptKeySeq* Init(char* szPassphrase, _TCHAR* szKeyFileName, size_t cbChunk = mChunkSize) {
		m_szPassphrase = auto_ptr<char>(new char[lstrlenA(szPassphrase) + 1]);
		lstrcpyA(m_szPassphrase.get(), szPassphrase);

		m_fHaveFile = (szKeyFileName != NULL);
		if (m_fHaveFile) {
			CSourceFileIO::Init(szKeyFileName, cbChunk);
		}
		return this;
	}

	/// \brief Open the file stream if any, otherwise just return true
	bool OutOpen() {
		return m_fHaveFile ? CSourceFileIO::OutOpen() : true;
	}

	/// \brief Close the file stream if any, otherwise just return true
	bool OutClose() {
		return m_fHaveFile ? CSourceFileIO::OutClose() : true;
	}

	/// \brief Start sending the passphrase string, then contents of the file
	/// \return A segment, first the string then from the file if any
	CSeg* In() {
		if (m_szPassphrase.get()) {
			size_t cb = lstrlenA(m_szPassphrase.get());
			if (cb) {
				return new CSeg(m_szPassphrase.release(), cb);
			}
			// If it's a zero-length passphrase, we just fall through
		}
		return m_fHaveFile ? CSourceFileIO::In() : new CSeg;
	}
};

/// \brief Manage the meta information of an Xecrets File Classic stream.
///
/// The base class is a std::list of CMetaSection. This is where
/// we define the various instances of CMetaSection in detail,
/// and interpret them.
class CXecretsFileMeta : public std::list<CMetaSection> {
	/// \brief Describe a eVersion section
	struct SVersion {
		BYTE oFileVersionMajor;             ///< FileMajor - Older versions cannot not read the format.
		BYTE oFileVersionMinor;             ///< FileMinor - Older versions can read the format, but will not retain on save.
		BYTE oVersionMajor;                 ///< Major - New release, major functionality change.
		BYTE oVersionMinor;                 ///< Minor - Changes, but no big deal.
		BYTE oVersionMinuscle;              ///< Minuscle - bugfix.
	};

	/// \brief Describe an eKeyWrap1 section, a standard 128-bit AES key.
	struct SKeyWrap1 {
		BYTE utKeyData[1 + sizeof TKey / 8][8]; ///< The Key Data (A + DEK).
		BYTE oSalt[16];                     ///< Salt, xor'ed with KEK before wrap/unwrap.
		BYTE oIter[4];                      ///< Custom number of iterations for work factor increase
	};

	/// \brief Describe an EncryptionInfo section.
	///
	/// This is where we keep Initializing Vector and the size
	/// of the plain text, excluding padding (but it might be compressed etc).
	struct SEncryptionInfo {
		BYTE aoPlainSize[8];                ///< The size of the plain text (still possibly compressed!)
		TBlock utIV;                        ///< The IV used for CBC encryption.
	};

	/// \brief Tell if compression is applied to the stream
	struct SCompressionFlag {
		BYTE aoCompFlag[sizeof DWORD];      ///< TRUE if compression was used.
	};

	/// \brief The actual data follows....
	struct SData {
		BYTE aoDataSize[8];                 ///< The size of the possibly padded/encrypted/compressed data
	};

	/// \brief The file modification and access times of the original encrypted file
	struct SFileTimes {
		FILETIME CreationTime;              ///< When the file is created
		FILETIME LastAccessTime;            ///< When the file most recently was accessed
		FILETIME LastWriteTime;             ///< When the file most recently was updated
	};

	/// \brief The section with the file modification times of the original file
	struct SFileInfo {
		BYTE aoFileTimes[sizeof SFileTimes];///< The various times associated with the file
	};

	TBlock m_IV;                            ///< IV for CBC decryption.
	size_t m_cbOffsetHMAC;                  ///< Offset in stream to data to HMAC
	size_t m_cbOffsetData;                  ///< Offset in stream to actual data to decrypt.
	TKey m_DecryptKey;                      ///< The current decryption key
	bool m_fKeyIsValid;                     ///< true if we have a valid key
	CAesWrap m_AesWrap;                     ///< Helper to unwrap the key after user entry of passphrase

	bool m_fOverwriteWithoutPrompt;         ///< From the GUI - Overwrite destination with no prompt
	bool m_fOpenAfter;                      ///< Attempt to launch application associated after decryption
	_TCHAR* m_szOutFolder;                  ///< The output directory, ptr owned by us

	/// \brief Get a meta data section
	///
	/// Get the raw data from a meta section, decrypt if necessary.
	/// Delete the pointer after use.
	/// \param eType The type of data section to get the raw data for
	/// \param pcb A pointer to a size_t where the size is placed. May be NULL.
	void* GetMetaData(TBlockType eType, size_t* pcb = NULL) {
		if (pcb) *pcb = 0;
		iterator i = FindType(eType);
		if (i == end()) {
			return NULL;
		}
		if (pcb) *pcb = i->Len();

		void* p = new unsigned char[i->Len()];
		if (!p) return NULL;

		memcpy(p, i->Data(), i->Len());
		if ((eType & eEncryptedFlag)) {
			if (m_fKeyIsValid) {
				// Initialize an AES structure with the Data Encrypting Key and the proper direction.
				CAes aesContext(CSubKey().Set(GetMasterDEK(), CSubKey::eHeaders).Get(), CAes::eCBC, CAes::eDecrypt);

				// Encrypt/Decrypt the block with default IV of zero.
				aesContext.Xblock((TBlock*)p, (TBlock*)p, (DWORD)i->Len() / sizeof TBlock);
			}
			else {
				return NULL;
			}
		}

		return p;
	}
public:
	/// \brief Initialize member variables
	CXecretsFileMeta() {
		m_cbOffsetData = m_cbOffsetHMAC = 0;
		m_fKeyIsValid = false;
		m_szOutFolder = NULL;
		m_fOverwriteWithoutPrompt = false;
		m_fOpenAfter = false;
	}

	/// \brief delete owned buffers
	~CXecretsFileMeta() {
		delete m_szOutFolder;
	}

	/// \brief Find the first section of the given type
	/// \param eType the type to find
	/// \return An iterator point to the found block, or CXecretsFileMeta::end()
	iterator FindType(TBlockType eType) {
		iterator i;
		for (i = begin(); i != end(); i++) {
			if (i->Type() == eType) {
				break;
			}
		}
		return i;
	}

	/// \brief Get the major version
	///
	/// We need the major version only, to verify that file version difference
	/// is not too large for us to understand the format.
	/// \return The Major file format version byte
	unsigned char FileVersionMajor() {
		iterator i = FindType(eVersion);
		if (i != end()) {
			return ((SVersion*)(i->Data()))->oFileVersionMajor;
		}
		return 0;
	}

	/// \brief Remember the offset where to start HMAC'ing
	///
	/// This is after the initial preamble, including the HMAC itself.
	/// Actually this is a design flaw in the format - the HMAC should
	/// have been appended instead. Too bad.
	/// \param cb The offset in the stream from start where HMAC'ing should begin
	void SetOffsetHMAC(size_t cb) {
		m_cbOffsetHMAC = cb;
	}

	/// \brief Get the stored offset to where HMAC'ing begins
	/// \return The offset.
	size_t GetOffsetHMAC() {
		return m_cbOffsetHMAC;
	}

	/// \brief Remember the offset where to start Decrypting
	///
	/// This is where the data of the file actually starts in one
	/// contiguous section, padded to encryption block size.
	/// \param cb The number of bytes to skip in the stream before decryption starts
	void SetOffsetData(size_t cb) {
		m_cbOffsetData = cb;
	}

	/// \brief Get the offset from stream start to the actual data to decrypt
	/// \return The offset.
	size_t GetOffsetData() {
		return m_cbOffsetData;
	}

	/// \brief Attempt to set a valid decryption key from a user-entered passphrase
	///
	/// Note that the key is always in Ansi.
	/// \param szKey The passphrase from the user. NUL-terminated. Ansi.
	/// \param szKeyFileName Path to a key file to append to the hash, or NULL.
	/// \return true if the key was the correct key for this file.
	bool SetDecryptKey(char* szKey, _TCHAR* szKeyFileName) {
		AxPipe::Stock::CPipeSHA1 SHA1;
		auto_ptr<CAxCryptKeySeq> pSource(new CAxCryptKeySeq);
		pSource->Init(szKey, szKeyFileName)->Append(SHA1)->Append(new CSinkNull)->Open()->Drain()->Close()->Plug();
		m_DecryptKey = *(TKey*)(SHA1.GetHash());
		ASSCHK(pSource->GetErrorCode() == 0, pSource->GetErrorMsg());

		iterator i = FindType(eKeyWrap1);
		ASSCHK(i != end(), _T("CXecretsFileMeta::SetDecryptKey() [No eKeyWrap1 found]"));

		// Get a pointer to the wrapped key
		SKeyWrap1* pKeyWrap = (SKeyWrap1*)(i->Data());

		// Try to unwrap it, and return the result.
		m_AesWrap.Init(*(unsigned int*)&pKeyWrap->oIter, sizeof TKey);
		return m_fKeyIsValid = (m_AesWrap.UnWrap(&m_DecryptKey, pKeyWrap->utKeyData, pKeyWrap->oSalt) == TRUE);
	}

	/// \brief Get a class-owned pointer to the IV (do not delete...)
	/// \return A pointer to the IV.
	TBlock* GetIV() {
		SEncryptionInfo* pEI = (SEncryptionInfo*)GetMetaData(eEncryptionInfo);
		if (pEI) {
			CopyMemory(&m_IV, &pEI->utIV, sizeof m_IV);
			delete pEI;
			return &m_IV;
		}
		return NULL;
	}

	/// \brief Get the length of the data stream, compressed or not
	/// \return The length in byte as a possibly very large number of the raw data stream.
	::longlong GetStreamSize() {
		SData* pD = (SData*)GetMetaData(eData);
		if (pD) {
			::longlong cb = *(::longlong*)pD->aoDataSize;
			delete pD;
			return cb;
		}
		return 0;
	}

	/// \brief Get the length of the decrypted data stream, possibly compressed.
	/// \return The length of the decrypted data, possibly a very large number...
	::longlong GetPlainSize() {
		SEncryptionInfo* pEI = (SEncryptionInfo*)GetMetaData(eEncryptionInfo);
		if (pEI) {
			::longlong cb = *(::longlong*)pEI->aoPlainSize;
			delete pEI;
			return cb;
		}
		return 0;
	}

	/// \brief Get the time of creation of the original file.
	/// \return The creation time in Windows standard format :-(
	FILETIME GetCreationTime() {
		SFileInfo* pFI = (SFileInfo*)GetMetaData(eFileInfo);
		FILETIME ft = { 0 };
		if (pFI) {
			ft = ((struct SFileTimes*)pFI->aoFileTimes)->CreationTime;
			delete pFI;
		}
		return ft;
	}

	/// \brief Get the time of last access of the original file.
	/// \return The creation time in Windows standard format :-(
	FILETIME GetLastAccessTime() {
		SFileInfo* pFI = (SFileInfo*)GetMetaData(eFileInfo);
		FILETIME ft = { 0 };
		if (pFI) {
			ft = ((struct SFileTimes*)pFI->aoFileTimes)->LastAccessTime;
			delete pFI;
		}
		return ft;
	}

	/// \brief Get the time of last write of the original file.
	/// \return The creation time in Windows standard format :-(
	FILETIME GetLastWriteTime() {
		SFileInfo* pFI = (SFileInfo*)GetMetaData(eFileInfo);
		FILETIME ft = { 0 };
		if (pFI) {
			ft = ((struct SFileTimes*)pFI->aoFileTimes)->LastWriteTime;
			delete pFI;
		}
		return ft;
	}

	/// \brief Get the Master Data Encrypting Key
	///
	/// The passphrase is used to wrap the MDEK. Here
	/// we unwrap it, using the (valid) passphrase. The MDEK
	/// in turn, is used to generate independent keys used for
	/// data encryption and header encryption etc.
	TKey* GetMasterDEK() {
		return (TKey*)m_AesWrap.GetKey();
	}

	/// \brief Get the HMAC from the headers
	/// \return An allocated pointer to the HMAC. Please delete after use.
	void* GetHMAC(size_t* cb) {
		return GetMetaData(ePreamble, cb);
	}

	/// \brief Check the headers to see if the data is compressed
	/// \return true if the data is compress and needs decompression after decryption
	bool IsCompressed() {
		SCompressionFlag* pCF = (SCompressionFlag*)GetMetaData(eCompressionFlag);
		if (pCF) {
			bool f = (*(DWORD*)pCF->aoCompFlag) != 0;
			delete pCF;
			return f;
		}
		// Old style file, always compressed.
		return true;
	}

	/// \brief Get the orginal file name in Unicode or Ansi char's from the headers.
	/// \return An allocated pointer to the name. Please delete after use.
	_TCHAR* GetFileName() {
		wchar_t* wzUnicodeFileName = (wchar_t*)GetMetaData(eUnicodeFileNameInfo);
		char* szFileName = NULL;
		if (wzUnicodeFileName != NULL) {
#if defined(UNICODE) || defined(_UNICODE)
			return wzUnicodeFileName;
#else
			int ccFileName = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, wzUnicodeFileName, -1, NULL, 0, "_", NULL);
			if (ccFileName != 0) {
				szFileName = (char*)new unsigned char[ccFileName];
				(void)WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, wzUnicodeFileName, -1, szFileName, ccFileName, "_", NULL);
			}
			delete[](unsigned char[])wzUnicodeFileName;
			wzUnicodeFileName = NULL;
			return szFileName;
#endif
		}

		szFileName = (char*)GetMetaData(eFileNameInfo);
		if (szFileName == NULL) {
			return NULL;
		}

#if defined(UNICODE) || defined(_UNICODE)
		int ccUnicodeFileName = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szFileName, -1, NULL, 0);
		if (ccUnicodeFileName != 0) {
			wzUnicodeFileName = (wchar_t*)new unsigned char[ccUnicodeFileName * sizeof(wchar_t)];
			if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, szFileName, -1, wzUnicodeFileName, ccUnicodeFileName) != ccUnicodeFileName) {
				delete[] wzUnicodeFileName;
				wzUnicodeFileName = NULL;
			}
		}

		delete[] szFileName;
		szFileName = NULL;

		return wzUnicodeFileName;
#else
		return szFileName;
#endif
	}

	/// \brief Get the filename to store to
	///
	/// Using the orignal file name as the default, and depending on
	/// user preferences concering overwrite prompting, possibly presenting
	/// a Save As dialog, get the final full path where to store the
	/// decrypted result. It uses a default folder as set by SetFolder(), and
	/// user preference flags as set by SetOverwriteWithoutPrompt().
	/// \param hWnd Parent window if user prompting is needed
	/// \return An allocated full path to a string. delete after use.
	_TCHAR* FileName(HWND hWnd = NULL) {
		//  First build the default name from the selected output folder,
		//  and the clear-text name
		auto_ptr<_TCHAR> szPath(new _TCHAR[_MAX_PATH]);

		// Get the original file name from the headers, and ask the user where
		// she really wants to put the result.
		auto_ptr<_TCHAR> szPlainFileName(GetFileName());

		// File names in the meta info is always Ansi, this code must handle Unicode
		// and non-unicode.
		wsprintf(szPath.get(), _T("%s"), GetFolder());
		DWORD dwFileAttributes = GetFileAttributes(szPath.get());
		PathAppend(szPath.get(), szPlainFileName.get());
		bool fIsValidDirectory = dwFileAttributes != INVALID_FILE_ATTRIBUTES && (dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

		// if we want to prompt when overwriting and the file exists, ask!
		if ((!DoOverwriteWithoutPrompt() && GetFileAttributes(szPath.get()) != INVALID_FILE_ATTRIBUTES) || !fIsValidDirectory) {
			// Build the filter string, i.e. for example "*.txt\0*.txt\0\0"
			// They don't make it easy by using nul chars...
			TCHAR* szPathExt = PathFindExtension(szPath.get());
			TCHAR szFilter[1024 + 1024];    // wsprintf guarantee (but we call it twice, so...
			if (szPathExt[0]) {
				wsprintf(szFilter, _T("*%s"), szPathExt);
				_TCHAR* szFilterPart2 = &szFilter[lstrlen(szFilter) + 1];
				wsprintf(szFilterPart2, _T("*%s"), szPathExt);
				szFilterPart2[lstrlen(szFilterPart2) + 1] = _T('\0');
			}
			else {
				// Copy default filter, if no extension.
				CopyMemory(szFilter, _T("*.*\0*.*\0"), sizeof _T("*.*\0*.*\0"));
			}

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = hWnd;
			ofn.lpstrFilter = szFilter;
			ofn.nFilterIndex = 1;
			ofn.lpstrDefExt = szPathExt[0] ? szPathExt + 1 : NULL;
			ofn.lpstrFile = szPath.get();
			ofn.nMaxFile = _MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
			if (!GetSaveFileName(&ofn)) {
				return NULL;
			}
		}

		return szPath.release();
	}

	/// \brief Set a default folder for the result.
	///
	/// Take ownership of the pointer to the out-folder, so it must be
	/// allocated by new, and will be delete'd here.
	/// \param szOutFolder An allocated string, delete'd by this class.
	void SetFolder(_TCHAR* szOutFolder) {
		delete m_szOutFolder;
		m_szOutFolder = szOutFolder;
	}

	/// \brief Set user option concering prompting if the output file exists.
	/// \param f Set to true to avoid a user dialog, even if the output exists already.
	void SetOverwriteWithoutPrompt(bool f) {
		m_fOverwriteWithoutPrompt = f;
	}

	/// \brief Check the user preference concerning prompting if the file exists.
	/// \return true if the output should not prompt, even if the output already exists.
	bool DoOverwriteWithoutPrompt() {
		return m_fOverwriteWithoutPrompt;
	}

	/// \brief Set user option if an application should be launched afterwards.
	/// \param f true to launch after decryption.
	void SetOpenAfter(bool f) {
		m_fOpenAfter = f;
	}

	/// \brief Check the user preference concerning application launch
	/// \return true if launch after decryption should be attempted.
	bool DoOpenAfter() {
		return m_fOpenAfter;
	}

	/// \brief Get the user preferred default output folder.
	/// \return An owned pointer. The caller should just drop it when done, not delete.
	_TCHAR* const GetFolder() {
		return m_szOutFolder;
	}
};

/// \brief Interface between the core working code and the user interface.
///
/// This class encapsulates the interface between the raw
/// data stream decryption, and the user interface (if any).
/// The data stream code should not be aware of windows,
/// but will call the public functions here to perform optional
/// operations such as displaying progress, and to perform
/// necessary operations such as retrieving passphrases.
/// It will also start the decryption in a separate thread, since
/// we need to keep the processing running while at the same
/// time keep the main window message loop active.
/// We also encapsulate progress bar support interface, so worker
/// thread can report it's progress.
///
/// This base class provides the foundation for an interface, but
/// contains no GUI specific code. Derive from this, and provide
/// the actual interface between working code and the user interface.
class CAxDecryptBase {
	HANDLE m_hThread;                       ///< Handle to the worker thread.
	_TCHAR* m_szFileName;                   ///< The encrypted input file.
	CAxPassphrase m_Passphrase;             ///< Prompt the user for a passphrase
	CVersion m_ver;                         ///< Get version info from ourselves

protected:
	bool m_fCancel;                         ///< Set asynch by the GUI to end prematurely
	int m_iFileCount;                       ///< Number of files processed
	HWND m_hWnd;                            ///< Handle to our parent window
	int m_iMsgId;                           ///< The message Id to send when done

private:
	/// \brief Just a way to get back into the class after starting work as a thread
	/// \param lpParameter The 'this' pointer
	/// \return The thread exit code
	static DWORD WINAPI CAxDecryptBase::WorkThreadProc(LPVOID lpParameter) {
		return ((CAxDecryptBase*)lpParameter)->Work();
	}

public:
	/// \brief Initialize member variables
	/// \param hWnd Parent window, with an active window procedure
	CAxDecryptBase(HWND hWnd = NULL) : m_Passphrase(hWnd) {
		m_iFileCount = 0;
		m_hWnd = hWnd;
		m_hThread = NULL;
		m_fCancel = false;
		m_szFileName = NULL;
	}

	/// \brief Wait for the active thread to finish and then clean up
	~CAxDecryptBase() {
		Wait();
		delete m_szFileName;
	}

	/// \brief Get the parent window handle
	/// \return A handle to the parent window
	HWND GetWnd() {
		return m_hWnd;
	}
	/// \brief Get version info concerning this self same exe
	/// \return A pointer to a class local CVersion, don't delete!
	CVersion* Version() {
		return &m_ver;
	}

	/// \brief Tell us the name of an input file
	/// \param szFileName An allocated string which we take ownership of! We'll delete it.
	void SetFile(_TCHAR* szFileName) {
		delete m_szFileName;
		m_szFileName = szFileName;
	}

	/// \brief Report the name of the input file
	/// \return A pointer to a class local buffer with the name. Don't delete!
	_TCHAR* GetFile() {
		return m_szFileName;
	}

	/// \brief Get the passphrase object
	/// \return A class local pointer to the passphrase object. Don't delete it!
	CAxPassphrase* Passphrase() {
		return &m_Passphrase;
	}

	/// \brief Start processing one file in a separate thread.
	/// \param iMsgId The message to send when done.
	void Start(int iMsgId) {
		m_iMsgId = iMsgId;
		m_fCancel = false;
		m_iFileCount = 0;
		DWORD dwThreadId;
		m_hThread = CreateThread(NULL, 0, WorkThreadProc, this, 0, &dwThreadId);
	}

	/// \brief The actual work, called by the thread procedure
	///
	/// This is where we do the actual work in a separate thread, but inside
	/// the class again. It's pure virtual here, since this is a base class
	/// that does nothing, you must derive.
	virtual int Work() = 0;

	/// \brief Tell the running thread, if any, that we wish to cancel.
	void Cancel() {
		m_fCancel = true;
	}

	/// \brief Wait for the running thread, if any, to exit
	/// \param dwWait The maximum amount of time to wait, in milliseconds.
	void Wait(DWORD dwWait = INFINITE) {
		if (m_hThread) {
			WaitForSingleObject(m_hThread, dwWait);
			m_hThread = NULL;
		}
	}

	/// \brief Initialize progress bar support
	///
	/// (This implementation is a no-op - refine in derived classes)
	/// \param cb The total number of bytes to process
	/// \param szFileName Path to the file name of the file to process.
	virtual void InitProgress(::longlong cb, _TCHAR* szFileName) {
		// Dummy references to make the compiler happy
		cb;
		szFileName;
	}

	/// \brief Report progress from the worker
	///
	/// (This implementation is a no-op - refine in derived classes)
	/// \param cb The number of bytes progressed so far
	virtual void Progress(::longlong cb) {
		// Dummy references to make the compiler happy
		cb;
	}

	/// \brief End progress bar support
	///
	/// (This implementation is a no-op - refine in derived classes)
	/// \param fOk true if the work successfully completed.
	virtual void EndProgress(bool fOk) {
		// Dummy references to make the compiler happy
		fOk;
	}

	/// \brief Get the folder selected for output, if any
	///
	/// (This implementation is a no-op - refine in derived classes)
	/// \param szFolder A buffer to place the folder name in
	/// \param cc The number of characters that fits in the provided buffer
	/// \return A pointer to szFolder, just for convenience
	virtual _TCHAR* GetFolder(_TCHAR* szFolder, size_t cc) {
		if (szFolder && cc) {
			szFolder[0] = '\0';
		}
		return szFolder;
	}

	/// \brief Report user preference concerning overwriting of output
	///
	/// The user may select to be prompted or not when the output would
	/// overwrite an existing file. Here we provide an interface to
	/// GUI code or whatever to get it.
	/// (This implementation is a default imp, always true, - refine in derived classes)
	/// \return true if we should overwrite without prompt.
	virtual bool OverwriteWithoutPrompt() {
		return true;
	}

	/// \brief Report user preference concering launch app after decrypt
	///
	/// The user may select that an attempt to launch after decryption shold
	/// be made.
	/// (This implementation is a default imp, always false, - refine in derived classes)
	/// \return true if we should attempt launch.
	virtual bool OpenAfterDecrypt() {
		return false;
	}
};

/// \brief A small helper class, it's only there to catch cancel requests by the user.
///
/// Let this section be part of the stream, for each segment passed down the line,
/// it will check the contents of a provided bool pointer location for a cancel condition.
class CPipeCancelCheck : public CPipe {
	bool* m_pfCancel;                       ///< Pointer to bool to check for cancel condition
public:
	/// \brief Initialize member variables
	CPipeCancelCheck() {
		m_pfCancel = NULL;
	}

	/// \brief Provide a pointer to a bool to check for cancel
	CPipeCancelCheck* Init(bool* pfCancel) {
		ASSPTR(pfCancel);
		*(m_pfCancel = pfCancel) = false;
		return this;
	}

	/// \brief Check the provided bool location for cancel
	///
	/// If cancel is indicated, drop the segment and set an error
	/// code, ERROR_CODE_ABORT
	/// \param pSeg A segment we just pass on after checking for cancel
	void Out(CSeg* pSeg) {
		if (*m_pfCancel) {
			pSeg->Release();
			SetError(ERROR_CODE_ABORT, _T("Decryption aborted"));
		}
		else {
			Pump(pSeg);
		}
	}
};

/// \brief Parse Xecrets File Classic headers
///
/// Parse headers and call a call-back when all headers
/// have been read and we're about to start sending
/// pure data downstream. We send all data downstream, pretty
/// much as it was received, as for example the HMAC calculator
/// needs it.
///
/// We also send a CFilterBlock::Signal() downstream, with a pointer to a meta
/// block of information, parsed and gleaned from the headers.
class CPipeAxCryptHeaders : public CFilterBlock {
	static const int m_iFileVersionMajor = 3; ///< The file version we understand.

	/// \brief The common header of all sections
	struct SHeader {
		BYTE aoLength[4];                   ///< Total length of header section
		BYTE oType;                         ///< Cast to TBlockType as appropriate.
	} m_utHeader;

	auto_ptr<CXecretsFileMeta> m_pMeta;         ///< All the meta information from the headers.
	THmac m_HMAC;                           ///< HMAC-SHA1-128 of header and data excl. preamble.
	CAxDecryptBase* m_pAxDecrypt;           ///< Connection back to controlling window etc
	CAutoSeg m_pSeg;                        ///< We need to buffer a bit locally too...

	/// \brief Locally buffering In()
	/// \param cb The number of bytes requested, or zero to return what we have
	/// \return A CSeg with data.
	/// \see CFilterBlock::In()
	CSeg* In(size_t cb) {
		// If we have something in the buffer...
		if (m_pSeg.get()) {
			if (!cb) {
				return m_pSeg.release();    // Return what we have
			}
			// If we have enough in the local buffer
			if (cb <= m_pSeg->Len()) {
				CSeg* pNewSeg = m_pSeg->Clone();
				pNewSeg->Len(cb);
				m_pSeg->Drop(cb);
				return pNewSeg;
			}
			// Not enough room - we need to complement. Create a 'large-enough' buffer
			size_t cbRest = cb - m_pSeg->Len();
			CSeg* pNewSeg = new CSeg(m_pSeg->PtrRd(), m_pSeg->Len(), cbRest);
			m_pSeg.release()->Release();

			CSeg* pRestSeg = ReadBlock(cbRest);
			if (pRestSeg) {
				CopyMemory(&pNewSeg->PtrWr()[pNewSeg->Len()], pRestSeg->PtrRd(), pRestSeg->Len());
				pNewSeg->Len(cb);
				pRestSeg->Release();
			}
			return pNewSeg;
		}
		return ReadBlock(cb);
	}

	/// \brief Push back a segment that we've already read.
	void InPush(CSeg* pSeg) {
		if (m_pSeg.get() && m_pSeg->Len()) {
			SetError(ERROR_CODE_DERIVED, _T("Internal error in InPush()"));
		}
		else {
			// The CAutoSeg takes care of deletion if non-NULL.
			m_pSeg = pSeg;
		}
	}

public:
	/// \brief Initialize member variables
	/// Initialize the constant major version we support also
	CPipeAxCryptHeaders() {
		m_pAxDecrypt = NULL;
	}

	/// \brief Connect with worker and GUI keeping track of meta info
	///
	/// The Worker/GUI interface is referenced via it's base-class, so
	/// as to virtualize the references, making this code also independent
	/// of details in the GUI.
	/// \param pAxDecrypt Pointer to Worker/GUI interface base class
	/// \return A pointer to this.
	CPipeAxCryptHeaders* Init(CAxDecryptBase* pAxDecrypt) {
		m_pAxDecrypt = pAxDecrypt;
		m_pMeta = auto_ptr<CXecretsFileMeta>(new CXecretsFileMeta);
		_TCHAR* szFolder = new _TCHAR[_MAX_PATH];
		m_pMeta->SetFolder(pAxDecrypt->GetFolder(szFolder, _MAX_PATH));
		m_pMeta->SetOverwriteWithoutPrompt(pAxDecrypt->OverwriteWithoutPrompt());
		m_pMeta->SetOpenAfter(pAxDecrypt->OpenAfterDecrypt());

		m_pSeg = NULL;
		return this;
	}

	/// \brief Distiguish ourselves with a uniqe run-time id
	///
	/// This is needed to send signals. This can be used to to get the
	/// class type from within the class, or to determine if a given Class Id
	/// refers to this class. See RTClassId() also.
	/// \return An adress guaranteed to be unique, but the same for all instances
	static void* ClassId() {
		static int i;
		return &i;
	}

	/// \brief A virtual access to the class
	///
	/// Enables all derived and base classes to correctly identify the type
	/// of this class, by comparing with CPipeAxCryptHeaders::ClassId().
	virtual void* RTClassId() {
		return ClassId();
	}

	/// \brief The main filter override
	///
	/// Process the input, which may consist of several appended encrypted
	/// files, but it must start with the Xecrets File GUID, so any preceeding
	/// data must be descarded before getting here.
	void InFilter() {
		for (;;) {
			m_pMeta->clear();               // Clear all header-info

			CAutoSeg pSeg(In(sizeof guidAxCryptFileIdInverse));
			// If the input is empty there is no more input, so we're at end of stream.
			if (!pSeg.get()) {
				// Input is empty.
				return;
			}
			if (!pSeg->Len()) {
				SetError(ERROR_CODE_XECRETSFILE, _T("Internal error, zero-length segment"));
				return;
			}
			if (pSeg->Len() != sizeof guidAxCryptFileIdInverse) {
				SetError(ERROR_CODE_XECRETSFILE, _T("Missing GUID"));
				return;
			}
			// Since we're storing the one's complement of the GUID, we can check for
			// equality this way.
			unsigned char s = 0;
			// Make the compiler generate proper code for 'for' based definitions
			for (int i = 0; (s == 0) && (i < sizeof guidAxCryptFileIdInverse); i++) {
				s |= pSeg->PtrRd()[i] ^ ((unsigned char*)&guidAxCryptFileIdInverse)[i] ^ 0xff;
			}
			if (s) {
				SetError(ERROR_CODE_XECRETSFILE, _T("Missing GUID"));
				return;
			}

			CSeg* pGUID = pSeg.release();   // Save for later

			SHeader* pHeader;
			size_t cbOffsetHMAC = sizeof guidAxCryptFileIdInverse;
			size_t cbOffsetData = sizeof guidAxCryptFileIdInverse;
			do {
				pSeg = In(sizeof SHeader);
				if (!pSeg.get() || pSeg->Len() != sizeof SHeader) {
					SetError(ERROR_CODE_XECRETSFILE, _T("Could not read expected header"));
					return;
				}
				pHeader = (SHeader*)pSeg->PtrRd();

				// Get the length of the header data, following the header-header
				size_t cbHeaderData = *(size_t*)(pHeader->aoLength) - sizeof SHeader;

				// Get extra data - do not ask for zero bytes from In(), it'll get all available.
				CAutoSeg pSegHeaderData = cbHeaderData ? In(cbHeaderData) : new CSeg(0);
				if (pSegHeaderData->Len() != cbHeaderData) {
					SetError(ERROR_CODE_XECRETSFILE, _T("Error reading header data"));
					return;
				}

				// Add this to what we don't want to decrypt
				cbOffsetData += sizeof SHeader + cbHeaderData;

				// Ensure proper sequencing etc
				switch ((TBlockType)pHeader->oType) {
				case ePreamble:
					// Preamble must be first, and only once.
					if (!m_pMeta->empty()) {
						SetError(ERROR_CODE_XECRETSFILE, _T("Preamble seen out of sequence"));
						return;
					}
					cbOffsetHMAC += sizeof SHeader + cbHeaderData;
					break;
				case eFileInfo:
				case eFileNameInfo:
				case eEncryptionInfo:
				case eCompressionInfo:
				case eCompressionFlag:
				case eVersion:
					// Ensure that only one of each of these are found.
					if (m_pMeta->FindType((TBlockType)pHeader->oType) != m_pMeta->end()) {
						SetError(ERROR_CODE_XECRETSFILE, _T("Illegal duplicate section found"));
						return;
					}
					break;
				case eKeyWrap1:
					// We support multiple wrappings of the key, at least potentially.
					break;
				default:
					// We silently ignore unknown meta sections
					break;
				}
				// Insert the section at the end of the meta-section list
				m_pMeta->insert(m_pMeta->end(), CMetaSection((TBlockType)pHeader->oType, memcpy(malloc(cbHeaderData), pSegHeaderData->PtrRd(), cbHeaderData), cbHeaderData));
			} while ((TBlockType)pHeader->oType != eData);
			// Check the file version (we only support this one version 3 currently)
			if (m_pMeta->FileVersionMajor() != m_iFileVersionMajor) {
				SetError(ERROR_CODE_XECRETSFILE, _T("New file version - cannot decrypt"));
				return;
			}
			// Check that we have a key
			if (m_pMeta->FindType(eKeyWrap1) == m_pMeta->end()) {
				SetError(ERROR_CODE_XECRETSFILE, _T("No data encrypting key found"));
				return;
			}

			// Now ask the user for a passphrase, and validate it (unless we have one)
			bool fRetry = false;
			while (!m_pMeta->SetDecryptKey(m_pAxDecrypt->Passphrase()->Passphrase(),
				m_pAxDecrypt->Passphrase()->KeyFileName())) {
				if (fRetry) {
					if (MessageBox(m_pAxDecrypt->GetWnd(),
						auto_ptr<_TCHAR>(ALoadString(IDS_WRONGPASSPHRASE)).get(),
						auto_ptr<_TCHAR>(ALoadString(IDS_AXDECRYPT)).get(),
						MB_ICONEXCLAMATION | MB_RETRYCANCEL) != IDRETRY) {
						SetError(ERROR_CODE_CANCEL, _T(""));
						return;
					}
				}
				switch (m_pAxDecrypt->Passphrase()->Show()) {
				case IDCANCEL:
					SetError(ERROR_CODE_CANCEL, _T(""));
					return;
				case IDYES:
					SetError(ERROR_CODE_MORE, _T(""));
					return;
				default:
					break;
				}
				fRetry = true;
			}

			// Initialize for progress monitoring
			::longlong cb = m_pMeta->GetStreamSize(), cbProgress = 0;
			m_pAxDecrypt->InitProgress(cb, auto_ptr<_TCHAR>(m_pMeta->GetFileName()).get());

			// Record the offset to the HMAC in the meta information
			m_pMeta->SetOffsetHMAC(cbOffsetHMAC);

			// Record the offset to data in the meta information
			m_pMeta->SetOffsetData(cbOffsetData);

			// We're just about to send data onwards, so let the next steps in the
			// pipe know about it.
			Sync();
			Signal(ClassId(), m_pMeta.get());       // Don't care if some-one listens or not.
			if (GetErrorCode()) {
				// Something bad happened when passing the signal.
				return;
			}

			//
			// We start by re-generating the data we've cached as headers, as later stages may need it.
			//
			Open();                         // Open the output channel, now that we've signalled
			Pump(pGUID);
			pGUID = NULL;                   // Done with this now.

			CXecretsFileMeta::iterator i;
			for (i = m_pMeta->begin(); i != m_pMeta->end(); i++) {
				SHeader header;
				header.oType = (BYTE)i->Type();
				*(AxPipe::int32*)header.aoLength = static_cast<AxPipe::int32>(i->Len() + sizeof header);

				// Here we make a copy of the header into the segment
				CSeg* pSeg = new CSeg(&header, sizeof header);
				Pump(pSeg);

				// Here we let the segment refer to the data in the Meta-list, as it will last
				// long enough anyway.
				pSeg = new CSeg(i->Len(), i->Data());
				Pump(pSeg);
			}

			// Now just pass through the rest of the data. Requesting zero means - take what we get.
			// We only read just enough and continue reading again if we have more to read.
			while (cb && (pSeg = In(0)).get() && pSeg->Len()) {
				// If we've received more than we need
				if (cb < static_cast<AxPipe::longlong>(pSeg->Len())) {
					CSeg* pLastSeg = pSeg->Clone();
					pLastSeg->Len((size_t)cb);
					pSeg->Drop((size_t)cb);
					Pump(pLastSeg);
					m_pAxDecrypt->Progress(cbProgress += cb);
					InPush(pSeg.release()); // Save this for later use.
					cb = 0;
				}
				else {
					pSeg->AddRef();         // AddRef since it'll CAutoSeg-destruct too.
					cb -= pSeg->Len();
					cbProgress += pSeg->Len();
					Pump(pSeg.get());
					m_pAxDecrypt->Progress(cbProgress);
				}
			}
			// Verify that we got all we needed.
			if (cb) {
				SetError(ERROR_CODE_XECRETSFILE, _T("File truncated or format error"));
			}
			Close();                        // Close the output - we're at end of this stream.
			m_pAxDecrypt->EndProgress(!GetErrorCode());
		}
	}
};

/// \brief Xecrets File Classic-specific derivation of HMAC_SHA1 calculation
///
/// This derived class will accept header info and signal an error
/// on mismatching HMAC
/// \see AxPipe::Stock::CPipeHMAC_SHA1
class CPipeAxHMAC_SHA1_128 : public AxPipe::Stock::CPipeHMAC_SHA1<128> {
	size_t m_cbHMAC;                        ///< The size of the HMAC from the meta data
	auto_ptr<unsigned char> m_pHMAC;        ///< The HMAC from the meta data
	CXecretsFileMeta* m_pMeta;                  ///< The meta data, passed via Signal() to OutSignal()
public:
	/// \brief Initialize member variables
	CPipeAxHMAC_SHA1_128() {
		m_pMeta = NULL;
		m_cbHMAC = 0;
	}

	/// \brief Receive the meta data from CPipeAxCryptHeaders
	/// \param vId The class id, expected is CPipeAxCryptHeaders::ClassId()
	/// \param p The pointer to meta data, CXecretsFileMeta
	/// \return true to pass the signal along downstream
	bool OutSignal(void* vId, void* p) {
		if (vId == CPipeAxCryptHeaders::ClassId()) {
			m_pMeta = (CXecretsFileMeta*)p;
		}
		return true;
	}

	/// \brief Setup for HMAC calculation before start of data
	///
	/// The base class will calculate the HMAC of a data stream, given
	/// a key and an offset whence to start from via a call to Init().
	/// What we do here is to call Init() with those parameters, gleaned from
	/// the meta data CXecretsFileMeta pointer we got via OutSignal.
	/// \return true to indicate the Close() should be cascaded downstream
	bool OutOpen() {
		ASSPTR(m_pMeta);                    // Just ensure that it's non-NULL

		// Give the base-class the key and the offset to start from.
		Init((AxPipe::Stock::TBits<128>*)CSubKey().Set(m_pMeta->GetMasterDEK(), CSubKey::eHMAC).Get(), m_pMeta->GetOffsetHMAC());

		// Set up the HMAC for processing.
		AxPipe::Stock::CPipeHMAC_SHA1<128>::OutOpen();

		// Get and save the HMAC and the size of it.
		m_pHMAC = auto_ptr<unsigned char>((unsigned char*)m_pMeta->GetHMAC(&m_cbHMAC));
		return true;
	}

	/// \brief Override OutClose() to check for HMAC-correctness
	/// \return true to cascade the Close() call downstream
	bool OutClose() {
		ASSPTR(m_pHMAC.get());              // Just ensure that it's non-NULL

		// Finalize HMAC processing
		AxPipe::Stock::CPipeHMAC_SHA1<128>::OutClose();

		// Check the HMAC that it is the same as is stored in the file, as long as we have
		// no other errors reported.
		if (!GetErrorCode()) {
			if (memcmp(m_pHMAC.get(), GetHash(), m_cbHMAC)) {
				SetError(ERROR_CODE_HMAC, _T("HMAC Error. File damaged."));
			}
		}
		return true;
	}
};

/// \brief Skip the headers from an Xecrets File Classic stream
///
/// Using info from the meta data about the offset to
/// the data, skip bytes before starting to pass it
/// along.
class CPipeAxCryptStripHeaders : public CPipe {
	size_t m_cbSkip;                        ///< The number of bytes left to skip
public:
	/// \brief Initialize member variables.
	CPipeAxCryptStripHeaders() {
		m_cbSkip = 0;
	}

	/// \brief Catch signal from CPipeAxCryptHeaders with meta data CXecretsFileMeta
	///
	/// This must be called before any data is sent via Pump() to Out(). Note that
	/// this may be called in a different thread context than Out().
	/// \param vId The Id, expected is CPipeAxCryptHeaders::ClassId()
	/// \param p The pointer, which will point to a CXecretsFileMeta where we get the offset to data
	/// \return true to pass the signal along down the line by the framework
	bool OutSignal(void* vId, void* p) {
		// Get how much we want to skip.
		if (vId == CPipeAxCryptHeaders::ClassId()) {
			m_cbSkip = ((CXecretsFileMeta*)p)->GetOffsetData();
		}
		return true;
	}

	/// \brief Pass data along, after skipping the given amount of bytes
	/// \param pSeg a segment with data
	void Out(CSeg* pSeg) {
		if (m_cbSkip) {
			if (m_cbSkip >= pSeg->Len()) {
				m_cbSkip -= pSeg->Len();    // May be more skipping
				pSeg->Release();            // The entire segment is to be skipped
				return;
			}
			pSeg->Drop(m_cbSkip);           // Part of the segment is to be used
			m_cbSkip = 0;                   // No more skipping
		}

		// Now pass it along to the next stage of the pipe
		Pump(pSeg);
	}
};

/// \brief AxDecrypt a raw stream of bytes.
///
/// To simplify the logic
/// here, we ust the filter chunk paradigm - we know that
/// the blocks will tend to arrive in nice chunks anyway.
/// This is the actual decryptor, it expects to only see
/// a stream of encrypted blocks, with padding.
/// It get's the key via a Signal() call, which it expects to
/// come from CPipeAxCryptHeaders.
class CPipeAxDecrypt : public CPipeBlock {
	CXecretsFileMeta* m_pMeta;                  ///< The pointer to the meta info, via Signal()
	CAes m_AesCtx;                          ///< Our decryption CBC context
	::longlong m_cb;                        ///< The number of bytes decrypted (excl. padding).

public:
	/// \brief Initialize member variables and the base class
	CPipeAxDecrypt() {
		CPipeBlock::Init(sizeof TBlock);
		m_pMeta = NULL;
	}

	/// \brief Receive a signal from upstream
	///
	/// We're expecting a call from CPipeAxCryptHeaders with a pointer
	/// to a CXecretsFileMeta, containing the key for the next file, and other
	/// meta information. Care must be taken since this call is made from
	/// potentially a different thread than the rest of the Out() family
	/// of functions. A Sync() before the call may be appropriate.
	/// \param vId The signal id, expected is CPipeAxCryptHeaders::ClassId()
	/// \param p A pointer to a CXecretsFileMeta
	/// \return true if the signal is to be continued to be passed down the line
	bool OutSignal(void* vId, void* p) {
		// Pick up keys and stuff
		if (vId == CPipeAxCryptHeaders::ClassId()) {
			m_pMeta = (CXecretsFileMeta*)p;

			// Initialize an AES structure with the Data Encrypting Key and the proper direction.
			m_AesCtx.Init(CSubKey().Set(m_pMeta->GetMasterDEK(), CSubKey::eData).Get(), CAes::eCBC, CAes::eDecrypt);
			m_AesCtx.SetIV(m_pMeta->GetIV());

			m_cb = m_pMeta->GetPlainSize();
		}
		return true;                        // Always pass the signal along
	}

	/// \brief Called at the end of one file's data stream
	///
	/// This is where we detect if there is some internal inconsistency
	/// between expected byte count and actual.
	/// \return true to pass the Close() call down the line.
	bool OutClose() {
		if (PartialBlock()) {
			SetError(ERROR_CODE_DERIVED, _T("Partial block detected in decrypt"));
		}
		return true;
	}

	/// \brief Decrypt a block and pass it along
	///
	/// Padding is removed, only actual plain text is passed along.
	/// \param pSeg The data to consume. Note that we're guaranteed a multiple of the block size here.
	void Out(CSeg* pSeg) {
		// Ensure we have a writeable destination
		CSeg* pOutSeg = GetSeg(pSeg->Len());
		ASSPTR(pOutSeg);

		// Here we're guaranteed an even multiple of the block size requested.
		m_AesCtx.Xblock((TBlock*)pSeg->PtrRd(), (TBlock*)pOutSeg->PtrWr(), (DWORD)pOutSeg->Len() / sizeof TBlock);

		pSeg->Release();                    // Release the source

		m_cb -= pOutSeg->Len();
		// We've just decrypted some padding, remove that from the output.
		if (m_cb < 0) {
			pOutSeg->Len(pOutSeg->Len() + (int)m_cb);
		}
		// A segment may be all padding - if so, just release it without passing it along.
		if (pOutSeg->Len()) {
			Pump(pOutSeg);
		}
		else {
			pOutSeg->Release();
		}
	}
};

/// \brief Inflate (decompress) with ZLib for Xecrets File Classic
///
/// Only inflate if the stream was compressed - otherwise
/// just pass through. Get the compress flag through the
/// meta information provided via Signal() to OutSignal()
/// in a pointer to CPipeXecretsFileMeta.
class CPipeAxDecompress : public AxPipe::Stock::CPipeInflate {
	bool m_fDecompress;                     ///< true if we're to inflate
public:
	/// \brief Intitialize member variables
	CPipeAxDecompress() {
		m_fDecompress = false;
	}

	/// \brief Receive a signal from upstream
	///
	/// If the caller is id CPipeAxCryptHeaders::ClassId(), then
	/// we interpret the argument as a pointer to a CPipeXecretsFileMeta
	/// class with the meta info, from which we pick up the 'are we
	/// compressed flag'.
	/// \param vId A ClassId, expecting CPipeAxCryptHeaders::ClassId()
	/// \param p A paramater, will be a CPipeXecretsFileMeta.
	/// \return true to pass the signal down the line.
	bool OutSignal(void* vId, void* p) {
		// Check if we need decompression
		if (vId == CPipeAxCryptHeaders::ClassId()) {
			// If there's a section with compression info - we're compressed.
			m_fDecompress = ((CXecretsFileMeta*)p)->IsCompressed();
		}
		return true;
	}

	/// \brief Handle open with or without compression
	/// \return the appropriate base class function return value
	bool OutOpen() {
		if (m_fDecompress) {
			return AxPipe::Stock::CPipeInflate::OutOpen();
		}
		else {
			return CPipe::OutOpen();
		}
	}

	/// \brief Process one segment, possibly inflating it
	///
	/// Depending on the state of the compress/decompress flag,
	/// do inflate or pass it along unmodified.
	/// \param pSeg A segment of data
	void Out(CSeg* pSeg) {
		if (m_fDecompress) {
			AxPipe::Stock::CPipeInflate::Out(pSeg);
		}
		else {
			Pump(pSeg);
		}
	}

	/// \brief Handle close with or without compression
	/// \return the appropriate base class function return value
	bool OutClose() {
		if (m_fDecompress) {
			return AxPipe::Stock::CPipeInflate::OutClose();
		}
		else {
			return CPipe::OutClose();
		}
	}
};

/// \brief Xecrets File Classic specific derivation which restores original file times
///
/// Using the file times gotten from the meta data in a CXecretsFileMeta
/// structure, passed via CPipe::Signal() to CPipe::OutSignal(), we
/// restore the original file times after the file is Close()'d.
/// This is also where we launch after decrytion, if that is a user
/// preference
/// The output file name is also gleaned from the meta info and
/// passed to CSinkFileIO::Init().
class CSinkAxDecryptFiles : public CSinkFileIO {
	/// \brief A collection of file times
	struct SFileTimes {
		FILETIME ftCT;                      ///< Creation Time
		FILETIME ftLAT;                     ///< Last Access Time
		FILETIME ftLWT;                     ///< Last Write (modification) Time
	} m_FileTimes;                          ///< The FILETIME's from the meta info
	bool m_fOpenAfter;                      ///< Should we launch after close?
	HWND m_hWnd;                            ///< Parent window for the launch, set in Init()
	auto_ptr<_TCHAR> m_szFileName;          ///< The output file name, from the meta info
public:
	/// \brief Initialize member variables
	CSinkAxDecryptFiles() : m_szFileName(NULL) {
		ZeroMemory(&m_FileTimes, sizeof m_FileTimes);
		m_fOpenAfter = false;
		m_hWnd = NULL;
	}

	/// \brief Get a parent window handle
	/// \param hWnd A handle the window to use as parent for launch of app
	/// \return A pointer to 'this'
	CSinkAxDecryptFiles* Init(HWND hWnd = NULL) {
		m_hWnd = hWnd;
		return this;
	}

	/// \brief Accept a CPipe::Signal() from upstream with the meta info
	///
	/// This is were we get the file times and the user preference concering
	/// launch after decrypt and the file name.
	/// \param vId The caller id, we're expecting CPipeAxCryptHeaders::ClassId()
	/// \param p The argument, we're expecting a pointer to a CXecretsFileMeta
	/// \return true to cascade the CPipe::Signal() downstream
	bool OutSignal(void* vId, void* p) {
		if (vId == CPipeAxCryptHeaders::ClassId()) {
			CXecretsFileMeta* pMeta = (CXecretsFileMeta*)p;
			m_FileTimes.ftCT = pMeta->GetCreationTime();
			m_FileTimes.ftLAT = pMeta->GetLastAccessTime();
			m_FileTimes.ftLWT = pMeta->GetLastWriteTime();
			m_fOpenAfter = pMeta->DoOpenAfter();
			m_szFileName = auto_ptr<_TCHAR>(pMeta->FileName(m_hWnd));
		}
		// Always pass the signal down the line.
		return true;
	}

	/// \brief Open the correct file name
	///
	/// We got the file name from the meta info, now we use it
	/// to pass to CSinkFileIO::Init to make it open the
	/// right file.
	/// \return true to cascade the Open() call, we let CSinkFileIO decide.
	bool OutOpen() {
		// Ensure that we got a file name, otherwise it's a cancel.
		if (!m_szFileName.get()) {
			SetError(ERROR_CODE_CANCEL, _T(""));
			return false;
		}
		CSinkFileIO::Init((const _TCHAR*)m_szFileName.get(), mChunkSize);
		return CSinkFileIO::OutOpen();
	}

	/// \brief Set the correct file times on the still-open file
	/// \return true to cascade the call (actually that's kind of irrelevant since we're a sink...)
	bool OutClose() {
		// Ensure that we got a file name, otherwise it's a cancel.
		if (!m_szFileName.get()) {
			SetError(ERROR_CODE_CANCEL, _T(""));
			return false;
		}

		// Ensure that the result has the proper file times set.
		ASSAPI(::SetFileTime(GetHandle(), &m_FileTimes.ftCT, &m_FileTimes.ftLAT, &m_FileTimes.ftLWT));

		bool fCascadeClose = CSinkFileIO::OutClose();

		if (!GetErrorCode()) {
			if (m_fOpenAfter) {
				// Check if we're about to launch an exe, it might be a virus...
				bool fYes = true;

				// We probably don't need a sfi, for this call, but the docs are unclear.
				SHFILEINFO sfi;
				ZeroMemory(&sfi, sizeof sfi);
				// We use SHGetFileInfo rather than GetBinaryType to work on Win9x.
				if (SHGetFileInfo(m_szFileName.get(), 0, &sfi, sizeof sfi, SHGFI_EXETYPE) != 0) {
					if (MessageBox(m_hWnd,
						auto_ptr<_TCHAR>(ALoadString(IDS_EXEWARN)).get(),
						auto_ptr<_TCHAR>(ALoadString(IDS_AXDECRYPT)).get(),
						MB_YESNO | MB_ICONWARNING) != IDYES) {
						fYes = false;
					}
				}
				if (fYes) {
					ShellExecute(m_hWnd, NULL, m_szFileName.get(), NULL, NULL, SW_SHOWNORMAL);
				}
			}
		}
		return fCascadeClose;
	}
};

// ---------------- This is where the 'Windows GUI' part of the code really begins ----------------

/// \brief Define some private windows messages for the GUI
enum WM_AXDECRYPT {
	// There are some semi-documented collisions in low WM_USER+, so we start at 10
	WM_AXDECRYPT_INFILE = WM_USER + 10,       ///< Change current input file name (lParam)
	WM_AXDECRYPT_START,                     ///< Start the actual decryption, disable as appropriate
	WM_AXDECRYPT_DONE,                      ///< End of decryption, signalled by the decryption it-self.
	WM_AXDECRYPT_OUTFILE,                   ///< Set the current plain-text decryption file name (lParam)
	WM_AXDECRYPT_NUMFILES,                  ///< Set the number of decrypted files (wParam)
	WM_AXDECRYPT_LAUNCHING,                 ///< Say that we're opening an application (lParam)
	WM_AXDECRYPT_QUICK,                     ///< Launch the quick just-decrypt decryption
	WM_AXDECRYPT_EXIT,                      ///< Signal to exit, after quick decrypt
};

/// \brief Define the User Interface specific parts.
///
/// This is where we implement the actual interface with
/// the GUI. The class depends on the dialog passed to the
/// constructor to have certain specific controls, and also
/// depends on the window procedure to implement certain
/// WM_USER+x messages with specific functionalities, see
/// MainDialogFunc() and IDD_AXDECRYPT.
/// \see MainDialogFunc().
class CAxDecryptSelf : public CAxDecryptBase {
	int m_IdProgress;                       ///< ID of the progress control
	int m_iShift;                           ///< Scaling factor for max in progress control
	_TCHAR m_szFileName[MAX_PATH];          ///< The current output file name
	bool m_fExitWhenDone;                   ///< Set to true to exit when done
public:
	/// \brief Initialize member variables
	///
	/// The dialog window passed must have a number of specific
	/// controls of specific types, this class depends on that.
	/// See the resource description.
	/// \param hWnd Handle to the main dialog window
	CAxDecryptSelf(HWND hWnd = NULL) : CAxDecryptBase(hWnd) {
		m_IdProgress = 0;
		m_iShift = 0;
		m_szFileName[0] = _T('\0');
		m_fExitWhenDone = false;
	}

	/// \brief Set up the progress control
	///
	/// Initialize the progress control by scaling the maximum value
	/// down to WORD size. Scaling is done by powers of two, via
	/// shifting, and the shift count is stored as m_iShift.
	/// Also accept the name of the file to decryp to.
	/// \param cb The size of the data to process in bytes.
	/// \param szFileName The name of the filename to decrypt to.
	void InitProgress(::longlong cb, _TCHAR* szFileName) {
		m_iShift = 0;
		ASSCHK(cb >= 0, _T("Negative progress size"));
		while (cb > 0xffff) {
			cb >>= 1;
			m_iShift++;
		}
		PostMessage(GetDlgItem(m_hWnd, IDC_PROGRESS), PBM_SETRANGE, 0, MAKELPARAM(0, (WORD)cb));
		PostMessage(GetDlgItem(m_hWnd, IDC_PROGRESS), PBM_SETPOS, 0, 0);
		ShowWindow(GetDlgItem(m_hWnd, IDC_PROGRESS), SW_SHOW);

		lstrcpyn(m_szFileName, szFileName, sizeof m_szFileName / sizeof m_szFileName[0]);
		PostMessage(m_hWnd, WM_AXDECRYPT_OUTFILE, 0, (LPARAM)m_szFileName);

		// Now we show the main window, if it was hidden previously.
		ShowWindow(m_hWnd, SW_SHOWNORMAL);
	}

	/// \brief The actual work to do
	///
	/// This function is exectued in it's own thread.
	/// It builds the complete pipe line, and is really the processing core
	/// of the whole decryption program.
	/// \return The thread status code. Zero for no error.
	int Work() {
		CSourceFileIO In;

		// Build the process sequence
		In.Append((new CPipeCancelCheck)->Init(&m_fCancel));
		In.Append((new AxPipe::Stock::CPipeFindSync)->Init(&guidAxCryptFileIdInverse, sizeof guidAxCryptFileIdInverse, true));
		In.Append((new CPipeAxCryptHeaders)->Init(this));
		In.Append(new CPipeAxHMAC_SHA1_128);
		In.Append(new CPipeAxCryptStripHeaders);
		In.Append(new CPipeAxDecrypt);
		In.Append(new CThread<CPipeAxDecompress>);
		In.Append((new CSinkAxDecryptFiles)->Init(m_hWnd));

		In.Init(GetFile(), mChunkSize);

		// Run the input through the pipe...
		int iErrorCode = In.Open()->Drain()->Close()->Plug()->GetErrorCode();

		switch (iErrorCode) {
		case ERROR_CODE_SUCCESS:
		case ERROR_CODE_CANCEL:
			break;
		case ERROR_CODE_MORE:
			SetExitWhenDone(false);
			break;
		default:
			MessageBox(m_hWnd, In.GetErrorMsg(), auto_ptr<_TCHAR>(ALoadString(IDS_AXDECRYPT)).get(), MB_OK);
			break;
		}

		PostMessage(m_hWnd, m_iMsgId, iErrorCode, (LPARAM)this);
		return iErrorCode;
	}

	/// \brief Get the folder selected by the user as output
	///
	/// The folder name is fetched from the dialog control IDC_FOLDER.
	/// \param szFolder The buffer where to store the name
	/// \param cc The maximum number of characters that fits in the buffer, incl. NUL.
	/// \return A pointer to szFolder, for convenience.
	_TCHAR* GetFolder(_TCHAR* szFolder, size_t cc) {
		if (szFolder && cc) {
			GetDlgItemText(m_hWnd, IDC_FOLDER, szFolder, (int)cc);
		}
		return szFolder;
	}

	/// \brief Report progress to the user.
	///
	/// The value reported should be less than or equal to the value
	/// given to InitProgress().
	/// \param cb The current progress counter
	void Progress(::longlong cb) {
		PostMessage(GetDlgItem(m_hWnd, IDC_PROGRESS), PBM_SETPOS, (WORD)(cb >> m_iShift), 0);
	}

	/// \brief Report the end of work and the final result
	/// \param fOk true if processing ended ok
	void EndProgress(bool fOk) {
		if (fOk) {
			m_iFileCount++;
		}
		PostMessage(m_hWnd, WM_AXDECRYPT_NUMFILES, m_iFileCount, (LPARAM)m_szFileName);
	}

	/// \brief Report user preference concerning overwriting of output
	///
	/// The user may select to be prompted or not when the output would
	/// overwrite an existing file. We get the preference from the
	/// check box IDC_OVERWRITE.
	/// \return true if we should overwrite without prompt.
	bool OverwriteWithoutPrompt() {
		return IsDlgButtonChecked(m_hWnd, IDC_OVERWRITE) == BST_CHECKED;
	}

	/// \brief Report user preference concering launch app after decrypt
	///
	/// The user may select that an attempt to launch after decryption shold
	/// be made. We get the preference from IDC_OPENAFTER, a checkbox in
	/// the dialog.
	/// \return true if we should attempt launch.
	bool OpenAfterDecrypt() {
		return IsDlgButtonChecked(m_hWnd, IDC_OPENAFTER) == BST_CHECKED;
	}

	/// \brief Get flag that tells if we should exit when done
	/// \return true if we should exit when done
	bool ExitWhenDone() {
		return m_fExitWhenDone;
	}

	/// \brief Set the flag determining if we're to exit when done
	/// \param fExitWhenDone Set to true to have us exit when done
	void SetExitWhenDone(bool fExitWhenDone) {
		m_fExitWhenDone = fExitWhenDone;
	}
};

/// \brief Support routine. Get an allocated string from a resource string table.
///
/// Get a string from a string table, but ensure that
/// that it's in a dynamically allocated buffer of sufficient
/// size. I see no real alterantive to the cut and try method
/// below. Aargh.
/// \param uId The string resource ID
/// \param hModule The module handle to use. Default is NULL to use the calling exe
/// \return An allocated string or NULL on error. Do remember to free.
_TCHAR*
ALoadString(UINT uId, HMODULE hModule) {
	if (!hModule) hModule = GetModuleHandle(NULL); // Default to calling exe
	size_t cbString = 0;
	_TCHAR* szString = NULL;
	DWORD dwLen;
	do {
		_TCHAR* t = (_TCHAR*)realloc(szString, (cbString += 50) * sizeof _TCHAR);
		if (!t) {
			free(szString);
			return NULL;
		}
		szString = t;
		dwLen = LoadString(hModule, uId, szString, (int)cbString);
		if (!dwLen) {
			free(szString);
			return NULL;
		}
	} while (dwLen >= (cbString - 1));
	return szString;
}

/// \brief Window procedure for the 'About' Box
/// \param hDlg Our main dialog window handle
/// \param message The windows message
/// \param wParam The WORD parameter
/// \param lParam The LONG parameter
/// \return TRUE if we processed the message
static LRESULT CALLBACK
About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
	lParam; // Dummy reference for C4100

	WORD wmId = LOWORD(wParam);
	//WORD wmEvent = HIWORD(wParam); // C4189
	_TCHAR* sz;

	switch (message) {
	case WM_INITDIALOG: {
		CVersion ver;
		_TCHAR szMsg[1024], * szNameVersion = ver.newNameVersionString(IDS_AXDECRYPT);

		ASSPTR(sz = ALoadString(IDS_ABOUTTITLE));
		wsprintf(szMsg, sz, szNameVersion);
		SetWindowText(hDlg, szMsg);
		delete sz;
		delete szNameVersion;

		ASSPTR(sz = ver.newLegalCopyright());
		SetDlgItemText(hDlg, IDC_COPYRIGHT, sz);
		delete sz;

		ASSPTR(sz = ALoadString(IDS_ABOUTMSG));
		wsprintf(szMsg, sz, auto_ptr<_TCHAR>(ALoadString(IDS_XECRETSFILE)).get());
		SetDlgItemText(hDlg, IDC_ABOUTMSG, szMsg);
		delete sz;

		ASSPTR(sz = ALoadString(IDS_XECRETSFILEURL));
		SetDlgItemText(hDlg, IDC_GETXECRETSFILE, sz);
		delete sz;

		return TRUE;
	}

	case WM_COMMAND:
		switch (wmId) {
		case IDOK:
		case IDCANCEL:
			EndDialog(hDlg, wmId);
			return TRUE;
		case IDC_GETXECRETSFILE:
		{
			// This is ugly - but it's no problem either, we're defining the string in the dialog
			_TCHAR szURL[200];
			GetDlgItemText(hDlg, IDC_GETXECRETSFILE, szURL, sizeof szURL / sizeof szURL[0]);
			ShellExecute(hDlg, NULL, szURL, NULL, NULL, SW_NORMAL);
			return TRUE;
		}
		default:
			break;
		}
		break;
	}
	return FALSE;
}

/// \brief Browse for folder callback
///
/// Used for the folder browse dialoge to set the initial directory. The
/// lpData is assumed to point to a buffer containing the directory path.
/// \param hwnd The parent window handle
/// \param uMsg The message
/// \param lParam A LONG parameter
/// \param lpData Pointer to data as appropriate
/// \return Always zero.
static int CALLBACK
BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData) {
	lParam; // Dummy reference for C4100
	switch (uMsg) {
		// Select the folder specified in lpData as a path
	case BFFM_INITIALIZED:
		if (lpData && *(_TCHAR*)lpData) {
			SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
		}
		break;
	default:
		break;
	}
	return 0;
}

/// \brief Support routine. Get the FQN of a module in an allocated string
///
/// Get the fully qualified name of a module, but ensure that
/// that it's in a dynamically allocated buffer of sufficient
/// size. I see no real alterantive to the cut and try method
/// below. Aargh.
/// \param hModule Handle to module to get name of. default NULL means calling module.
/// \return An allocated string with the name. May be NULL on error. Remember to free.
static _TCHAR*
AGetModuleFileName(HMODULE hModule = NULL) {
	if (hModule == NULL) hModule = GetModuleHandle(NULL);

	size_t cbFileName = 0;
	_TCHAR* szFileName = NULL;
	DWORD dwLen;
	do {
		_TCHAR* t = (_TCHAR*)realloc(szFileName, (cbFileName += MAX_PATH) * sizeof _TCHAR);
		if (!t) {
			free(szFileName);
			return NULL;
		}
		szFileName = t;
		dwLen = GetModuleFileName(hModule, szFileName, (DWORD)cbFileName);
		if (!dwLen) {
			free(szFileName);
			return NULL;
		}
	} while (dwLen >= (cbFileName - 1));
	return szFileName;
}

/// \brief Check if there is any Xecrets File Classic headers in a file
/// \param szPath The path to the file to check
/// \return true if we recognize this as a proper Xecrets File Classic file
static bool
IsAxCryptFile(_TCHAR* szPath) {
	CSourceFileIO In;

	In.Append((new AxPipe::Stock::CPipeFindSync)->Init(&guidAxCryptFileIdInverse, sizeof guidAxCryptFileIdInverse, true));
	In.Append(new CSinkCheckAny);
	int iErrorCode = In.Init(szPath, mChunkSize)->Open()->Drain()->Close()->Plug()->GetErrorCode();
	return iErrorCode == XECRETSFILE_CODE_DATA;
}

/// \brief Copy an AxDecrypt file, but not the attached part if any.
///
/// The calling signature is modelled on the Win32 API CopyFile.
/// \param szMe Path to us.
/// \param szCopy Path to the copy.
/// \param fFailIfExists Fail the operation if the file already exists.
/// \return TRUE if the copy succeeded.
BOOL
AxDecryptCopyFile(_TCHAR* szMe, _TCHAR* szCopy, BOOL fFailIfExists) {
	// Honor the fail-if-exist request.
	if (fFailIfExists && (GetFileAttributes(szCopy) != INVALID_FILE_ATTRIBUTES)) {
		return FALSE;
	}

	CSourceFileIO fileMe;
	fileMe.Append((new AxPipe::Stock::CPipeFindSync)->Init(&guidAxCryptFileIdInverse, sizeof guidAxCryptFileIdInverse, true, -1));
	fileMe.Append((new AxPipe::CSinkFileIO)->Init(szCopy, mChunkSize));
	int iErrorCode = fileMe.Init(szMe, mChunkSize)->Open()->Drain()->Close()->Plug()->GetErrorCode();
	return iErrorCode != 0 ? FALSE : TRUE;
}

inline _TCHAR* lstrchr(const _TCHAR* string, int c) {
	while (*string && *string != c) {
		++string;
	}
	if (*string) {
		return (_TCHAR*)string;
	}
	return NULL;
}

/// \brief Our main GUI Application Window, dialog-based thingy.
/// \param hwndDlg The handle to us
/// \param uMsg The message to us
/// \param wParam the WORD parameter to us
/// \param lParam the LONG parameter to us
/// \return TRUE if we processed the message.
static INT_PTR CALLBACK
MainDialogFunc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	_TCHAR szMsg[1024 > MAX_PATH ? 1024 : MAX_PATH]; ///< A message buffer. wsprintf guarantees 1024. Also used for paths.
	_TCHAR* sz;                             ///< Another message buffer
	int wmId, wmEvent;                      ///< Helper variables for WM_COMMAND
	/// \brief A pointer to our controlling structure, set in GWL_USERDATA
	CAxDecryptSelf* pAxDecrypt = (CAxDecryptSelf*)(LONG_PTR)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

	switch (uMsg) {
	case WM_INITDIALOG:
#pragma warning ( push )
#pragma warning ( disable : 4244 )
		SetWindowLongPtr(hwndDlg, GWLP_USERDATA, (LONG_PTR)(pAxDecrypt = new CAxDecryptSelf(hwndDlg)));
#pragma warning ( pop )
		// Determine the default state of the option check boxes
		CheckDlgButton(hwndDlg, IDC_OVERWRITE, BST_UNCHECKED);
		CheckDlgButton(hwndDlg, IDC_OPENAFTER, BST_UNCHECKED);

		SetDlgItemText(hwndDlg, IDC_STATUS, _T(""));

		sz = ALoadString(IDS_AXDECRYPT);
		SetWindowText(hwndDlg, sz);
		delete sz;

		PostMessage(hwndDlg, WM_AXDECRYPT_DONE, 0, 0);
		break;

	case WM_DESTROY:
		pAxDecrypt->Cancel();
		pAxDecrypt->Wait();
		delete pAxDecrypt;
		PostQuitMessage(0);
		break;

	case WM_CLOSE:
		DestroyWindow(hwndDlg);
		break;

	case WM_AXDECRYPT_INFILE:
		// Change current input file name, lParam is the name, which we take ownership of
		sz = ALoadString(IDS_FILEMSG);
		wsprintf(szMsg, sz, PathFindFileName((_TCHAR*)lParam));
		delete sz;
		SetDlgItemText(hwndDlg, IDC_PROMPT, szMsg);

		sz = ALoadString(IDS_AXDECRYPT);
		wsprintf(szMsg, _T("%s - %s"), sz, PathFindFileName((_TCHAR*)lParam));
		delete sz;
		SetWindowText(hwndDlg, szMsg);

		// strcpy without including strcpy()
		lstrcpy(szMsg, (_TCHAR*)lParam);
		PathRemoveFileSpec(szMsg);
		SetDlgItemText(hwndDlg, IDC_FOLDER, szMsg);

		// SetFile() takes ownership of the allocated string passed as file name
		pAxDecrypt->SetFile((_TCHAR*)lParam);

		// Clear status when opening a new file
		SetDlgItemText(hwndDlg, IDC_STATUS, _T(""));

		// Enable/Disable appropriate controls etc.
		EnableWindow(GetDlgItem(hwndDlg, IDC_DECRYPT), TRUE);
		break;

	case WM_AXDECRYPT_QUICK:
		pAxDecrypt->Passphrase()->MoreInstead(true);
		pAxDecrypt->SetExitWhenDone(true);
		PostMessage(hwndDlg, WM_AXDECRYPT_START, 0, 0);
		break;

	case WM_AXDECRYPT_EXIT:
		// We're in quick mode, exit after completed job, just displaying a final message.
		GetDlgItemText(hwndDlg, IDC_STATUS, szMsg, sizeof szMsg / sizeof szMsg[0]);
		szMsg[sizeof szMsg / sizeof szMsg[0] - 1] = _T('\0');
		MessageBox(hwndDlg, szMsg, auto_ptr<_TCHAR>(ALoadString(IDS_AXDECRYPT)).get(), MB_OK);
		PostQuitMessage((int)wParam);
		break;

	case WM_AXDECRYPT_START:
		// Start the actual decryption, disable as appropriate
		EnableWindow(GetDlgItem(hwndDlg, IDM_FILE_OPEN), FALSE);
		EnableWindow(GetDlgItem(hwndDlg, IDCANCEL), TRUE);
		// Start the actual work, in a separate thread, to keep the message loop going
		pAxDecrypt->Start(WM_AXDECRYPT_DONE);
		break;

	case WM_AXDECRYPT_DONE:
		// End of decryption, signalled by the decryption it-self.
		// Re-enable controls as appropriate.
		// wParam is the exit code
		if (wParam == 0) {
			pAxDecrypt->SetFile(NULL);

			sz = ALoadString(IDS_AXDECRYPT);
			SetWindowText(hwndDlg, sz);
			delete sz;

			sz = ALoadString(IDS_TOOPEN);
			SetDlgItemText(hwndDlg, IDC_PROMPT, sz);
			delete sz;

			EnableWindow(GetDlgItem(hwndDlg, IDC_DECRYPT), FALSE);
			SetFocus(GetDlgItem(hwndDlg, IDC_PASSPHRASE));
			if (pAxDecrypt->ExitWhenDone()) {
				PostMessage(hwndDlg, WM_AXDECRYPT_EXIT, 0, 0);
			}
		}
		else {
			// An error occured, for example cancel.
			ShowWindow(hwndDlg, SW_SHOW);
			EnableWindow(GetDlgItem(hwndDlg, IDC_DECRYPT), TRUE);
			SetFocus(GetDlgItem(hwndDlg, IDC_DECRYPT));
			pAxDecrypt->SetExitWhenDone(false);
		}

		EnableWindow(GetDlgItem(hwndDlg, IDM_FILE_OPEN), TRUE);
		EnableWindow(GetDlgItem(hwndDlg, IDCANCEL), FALSE);
		ShowWindow(GetDlgItem(hwndDlg, IDC_PROGRESS), SW_HIDE);
		break;

	case WM_AXDECRYPT_OUTFILE:
		// Set the current plain-text decryption file name
		sz = ALoadString(IDS_DECRYPTING);
		wsprintf(szMsg, sz, PathFindFileName((_TCHAR*)lParam));
		delete sz;

		SetDlgItemText(hwndDlg, IDC_STATUS, szMsg);
		break;

	case WM_AXDECRYPT_NUMFILES:
		// Set the number of decrypted files.
		sz = ALoadString(IDS_STATUS);
		wsprintf(szMsg, sz, wParam);
		delete sz;

		SetDlgItemText(hwndDlg, IDC_STATUS, szMsg);
		break;

	case WM_AXDECRYPT_LAUNCHING:
		// Say that we're opening an application.
		sz = ALoadString(IDS_OPENING);
		wsprintf(szMsg, sz, PathFindFileName((_TCHAR*)lParam));
		delete sz;

		SetDlgItemText(hwndDlg, IDC_STATUS, szMsg);
		break;

	case WM_COMMAND:
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch (wmId) {
		case IDC_ABOUT:
		case IDM_HELP_ABOUT:
			DialogBox(GetModuleHandle(NULL), (LPCTSTR)IDD_ABOUTBOX, hwndDlg, (DLGPROC)About);
			break;
		case IDM_FILE_KEY:
		case IDC_PASSPHRASE:
			pAxDecrypt->Passphrase()->Show();
			break;
		case IDC_DECRYPT:
			pAxDecrypt->Passphrase()->MoreInstead(false);
			PostMessage(hwndDlg, WM_AXDECRYPT_START, 0, 0);
			break;
		case IDC_BROWSE: {
			GetDlgItemText(hwndDlg, IDC_FOLDER, szMsg, sizeof szMsg / sizeof szMsg[0]);

			BROWSEINFO bi;
			bi.hwndOwner = hwndDlg;
			bi.pidlRoot = NULL;
			bi.pszDisplayName = szMsg;
			bi.lpszTitle = ALoadString(IDS_FOLDER);
			bi.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS;
			bi.lpfn = BrowseCallbackProc;
			bi.lParam = (LPARAM)szMsg;
			bi.iImage = 0;

			LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
			delete (void*)bi.lpszTitle;

			if (pidl) {
				if (SHGetPathFromIDList(pidl, szMsg) == TRUE) {
					SetDlgItemText(hwndDlg, IDC_FOLDER, szMsg);
				}
				LPMALLOC pMalloc;
				if (SHGetMalloc(&pMalloc) == NOERROR) {
					pMalloc->Free(pidl);
				}
			}

			break;
		}
		case IDM_FILE_OPEN: {
			// Get a file name, and communicate it as the current
			// Allocate a buffer and zero-initialize it
			auto_ptr<_TCHAR> szFileName(new _TCHAR[_MAX_PATH]);
			ASSPTR(szFileName.get());
			szFileName.get()[0] = _T('\0');

			// Build a filter string, complicated by the fact that it uses embedded
			// nul-values...
			_TCHAR* szExt;
			ASSPTR(szExt = ALoadString(IDS_AXEXT));
			_TCHAR szFilter[1024];
			// Use backslash as placeholder for extra nul:s
			wsprintf(szFilter, _T("*%s\\*%s\\*.exe\\*.exe\\"), szExt, szExt);
			delete szExt;
			// Now replace the backslashes with the nul:s
			for (szExt = lstrchr(szFilter, _T('\\')); szExt; szExt = lstrchr(szExt + 1, _T('\\'))) {
				*szExt = '\0';
			}

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFilter = szFilter;
			ofn.lpstrFile = szFileName.get();
			ofn.nMaxFile = _MAX_PATH;
			ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

			// Ask the user for a file to decrypt, or if he cancels, just return
			if (GetOpenFileName(&ofn)) {
				// Make the name presentable, regardless of it's source. Yes, we can use the input as the output buffer.
				DWORD dwOutLen = GetLongPathName(szFileName.get(), szFileName.get(), _MAX_PATH);
				ASSAPI((dwOutLen != 0) && (dwOutLen <= _MAX_PATH));

				PostMessage(hwndDlg, WM_AXDECRYPT_INFILE, 0, (LPARAM)szFileName.release());
			}
			break;
		}
		case IDM_FILE_COPYAXDECRYPTTO: {
			// Get a path to oursevles
			auto_ptr<_TCHAR> szMe(AGetModuleFileName());
			ASSPTR(szMe.get());

			TCHAR szFileName[MAX_PATH];
			if (IsAxCryptFile(szMe.get())) {
				lstrcpy(szFileName, auto_ptr<_TCHAR>(ALoadString(IDS_DEFAULTFILENAME)).get());
			}
			else {
				lstrcpy(szFileName, PathFindFileName(szMe.get()));
			}

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = hwndDlg;
			ofn.lpstrFilter = _T("*.exe\0*.exe\0");
			ofn.nFilterIndex = 1;
			ofn.lpstrDefExt = _T("exe");
			ofn.lpstrFile = szFileName;
			ofn.nMaxFile = sizeof szFileName / sizeof szFileName[0];
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

			// Ask the user for a file to decrypt, or if he cancels, just return
			if (GetSaveFileName(&ofn)) {
				if (AxDecryptCopyFile(szMe.get(), szFileName, FALSE)) {
					sz = ALoadString(IDS_COPYOK);
				}
				else {
					sz = ALoadString(IDS_COPYNOTOK);
				}
				_TCHAR szMsg[1024];
				wsprintf(szMsg, sz, auto_ptr<_TCHAR>(ALoadString(IDS_AXDECRYPT)).get());
				SetDlgItemText(hwndDlg, IDC_STATUS, szMsg);
				delete sz;
			}
			break;
		}
		case IDCANCEL:
			pAxDecrypt->Cancel();
			break;
		case IDM_FILE_EXIT:
			DestroyWindow(hwndDlg);
			break;
		case IDC_HELPBUTTON:
		case IDM_HELP_CONTENTS: {
			_TCHAR* szName = ALoadString(IDS_AXDECRYPT);
			sz = ALoadString(IDS_HELPMSG);
			MessageBox(hwndDlg, sz, szName, MB_OK | MB_ICONINFORMATION);
			delete sz;
			delete szName;
			break;
		}
		default:
			return FALSE;
			break;
		}
		return TRUE;
		break;
	default:
		return FALSE;
		break;
	}
	return TRUE;
}

/// \brief Create and show main window
/// \param hInstance Our instance handle
/// \param nCmdShow Default show mode
/// \return The handle to the created main window
static HWND
InitInstance(HINSTANCE hInstance, int nCmdShow) {
	nCmdShow; // Dummy reference for C4100
	// We're a dialogbased app, so load the dialog
	HWND hWnd = CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_AXDECRYPT), NULL, MainDialogFunc, 0);

	if (!hWnd) {
		return NULL;
	}

	// Set ourselves as the first current file name
	auto_ptr<_TCHAR> szMe(AGetModuleFileName());
	ASSPTR(szMe.get());
	if (IsAxCryptFile(szMe.get())) {
		auto_ptr<_TCHAR> szLongMe(new _TCHAR[_MAX_PATH]);
		DWORD dwLongLen = GetLongPathName(szMe.get(), szLongMe.get(), _MAX_PATH);
		ASSAPI((dwLongLen != 0) && (dwLongLen < _MAX_PATH));
		PostMessage(hWnd, WM_AXDECRYPT_INFILE, 0, (LPARAM)szLongMe.release());
		PostMessage(hWnd, WM_AXDECRYPT_QUICK, 0, 0);
	}
	else {
		SetFocus(hWnd);
		ShowWindow(hWnd, SW_SHOWNORMAL);
		UpdateWindow(hWnd);
	}

	return hWnd;
}

/// \brief Entry point to the program
///
/// Initialize AxPipe, Common controls, CoMem, application main window
/// Start the message loop, and exit the program when the user wants.
/// \param hInstance Our instance handle
/// \param hPrevInstance The previous instance if any
/// \param lpCmdLine The command line used to launch us
/// \param nCmdShow The default window show mode to use
/// \return The exit code of the program. 0 for ok, non-zero for problems.
int APIENTRY
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	lpCmdLine; // Dummy reference for C4100
	hPrevInstance; // Dummy reference for C4100

	CGlobalInit axPipeInit;                 // There just needs to be one instance of this.
	// Perform application initialization:
	InitCommonControls();
	CoInitialize(NULL);

	HWND hmainWnd;
	if ((hmainWnd = InitInstance(hInstance, nCmdShow)) == NULL) {
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_AXDECRYPT);

	// Main message loop:
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!IsDialogMessage(hmainWnd, &msg) && !TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	CoUninitialize();
	return (int)msg.wParam;
}