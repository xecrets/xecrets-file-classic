/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2023 Svante Seleborg/Axon Data, All rights reserved.

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
	CHeader.cpp						Define format and operations on the headers in the wrapped
									output file.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2002-08-11              Rel 1.2
									2003-06-23              1.4d1.5 - Remove std file I/O

*/
#include	"StdAfx.h"
#include	"CHeader.h"
#include	"CCryptoRand.h"
#include	"CXform.h"
#include	"../XecretsFileCommon/CVersion.h"
#include    "../XecretsFileCommon/CRegistry.h"
#include "../AxPortLib/ttstring.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CHeader.cpp"
//
//	The value of the constant according to FIPS recommendations
//
static BYTE aoKeyWrapA[8] = {
	0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};
//
//	This is the format of the header - it is intended to be upwards extendable
//	and of variable length, with no byte ordering problems...
//
//  First of all comes the 16-byte GUID. Then a number of header sections.
//
//	The total header consists of any number of sections, each always
//	always specifying the total length including the length itself.
//
//	The length is stored small-endian, i.e. least significant byte first.
//
//	After the headers, follows the raw data, compressed, encrypted and padded
//  as the case may be. The length of this is
//	stored in the data section header, and must thus also be checked.
//
//	Theses sections are defined currently:
//
//	Preamble:		Containing version information and other info to validate the file itself.
//	KeyWrap1:		Data encrypting key, wrapped with a key encrypting key
//	Version:		File and program version information
//	FileNameInfo	Original file name
//	EncryptionInfo	Sizes of the original data file before encryption
//	CompressionInfo	Indicates that the data is compressed and the sizes.
//	FileInfo,		Time stamps and size of the original file
//	Data:			Actual data always follows.
//
//	The format will support future upgrades to multiple/alternate algorithms etc.
//
//	The header sections are linked in memory in a list. The Preamble is always
//	considered to be the first and only such. Other sections may, or may not,
//  exist more than one time.
//
//	The Data section in the file is the end of headers.
//	The Preamble section is thus the 'root' of the list.
//
//
//
//  Helper, used to handle cases where we might want to conditionally continue
//  even on error.
//
void
ConditionalThrow(TAssert& utErr, DWORD dwMsgId) {
	bool fContinue = false;
	// If we have the 'try with broken file set', we let the user have the option to continue.
	if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValTryBrokenFile).GetDword(FALSE)) {
		if (utErr.LastError() == dwMsgId) {
			if (CMessage().AppMsg(dwMsgId).ShowDialog(MB_OKCANCEL | MB_ICONERROR) == IDOK) {
				fContinue = true; // If the users says 'OK' anyway, let's try decryption anyway.
			}
		}
	}
	if (!fContinue) {
		utErr.Throw();              // Throw it really.
	}
}

CHeaderHeader::CHeaderHeader() {
	m_pNext = NULL;
	m_pvHeaderData = NULL;
	m_iHeaderSize = 0;
}

CHeaderHeader::~CHeaderHeader() {
	// This will cause a delete of the rest of the list too
	if (m_pvHeaderData != NULL) delete m_pvHeaderData;
	if (m_pNext != NULL) delete m_pNext;
}
//
// Set the type indicator so we can differentiate what type of object it
// is when we only have a CHeaderHeader *.
//
void
CHeaderHeader::SetType(TBlockType eType) {
	m_utHeader.oType = (BYTE)eType;
}
//
//	Write all headers starting with this to a file.
//
void
CHeaderHeader::PutAll(CFileIO& rFile) {
	Put(rFile);
	if (m_pNext != NULL) m_pNext->PutAll(rFile);
}
//
//	Return complete length on file of this header section
//
DWORD
CHeaderHeader::Size() {
	return sizeof m_utHeader + m_iHeaderSize;
}
//
// Return the length of this complete header, and all that follows.
//
DWORD
CHeaderHeader::SizeAll() {
	return Size() + (m_pNext == NULL ? 0 : m_pNext->SizeAll());
}
//
//	Take a peek at the next header type, leave file position unchanged.
//	Throw TAssert exception on error.
//
TBlockType
CHeaderHeader::PeekType(CFileIO& rFile) {
	SHeader utTmp;
	size_t cb = sizeof utTmp;
	rFile.ReadData(&utTmp, &cb);
	CAssert(cb == sizeof utTmp).App(MSG_INTERNAL_ERROR, _T("CHeaderHeader::PeekType [Short read]")).Throw();

	// Backup file pointer
	rFile.SetFilePointer(rFile.GetFilePointer() - sizeof utTmp);
	return (TBlockType)utTmp.oType;
}
//
//	Load the data-structure from file. We will always read the entire structure on disk.
//	Ensure that data format changes change version numbers accordingly.
//	Probably need a test for 'reasonable' values of data lengths to handle bad files...
//
void
CHeaderHeader::Get(CFileIO& rFile) {
	size_t cb;

	cb = sizeof m_utHeader;
	rFile.ReadData(&m_utHeader, &cb);
	CAssert(cb == sizeof m_utHeader).App(MSG_INTERNAL_ERROR, _T("CHeaderHeader::Get [Short read(1)]")).Throw();

	// Allocate room for the header on file, it already meets alignment requirements
	// so no extra alignment is needed here.
	AllocateHeader(GetDW(m_utHeader.aoLength) - sizeof m_utHeader, 1);
	cb = m_iHeaderSize;
	rFile.ReadData(m_pvHeaderData, &cb);
	CAssert(cb == m_iHeaderSize).App(MSG_INTERNAL_ERROR, _T("CHeaderHeader::Get [Short read(2)]")).Throw();
}
//
//	Write the data-structure to a file
//
void
CHeaderHeader::Put(CFileIO& rFile) {
	SetDW(m_utHeader.aoLength, sizeof m_utHeader + m_iHeaderSize);

	size_t cb;

	cb = sizeof m_utHeader;
	rFile.WriteData(&m_utHeader, &cb);
	CAssert(cb == sizeof m_utHeader).App(MSG_INTERNAL_ERROR, _T("CHeaderHeader::Get [Short write(1)]")).Throw();

	cb = m_iHeaderSize;
	rFile.WriteData(m_pvHeaderData, &cb);
	CAssert(cb == m_iHeaderSize).App(MSG_INTERNAL_ERROR, _T("CHeaderHeader::Get [Short write(2)]")).Throw();
}
//
//	Byte order/Endianess-independent loading of a DWORD
//	from a byte array
//	All integer type data is stored little-endian on file.
//
DWORD
CHeaderHeader::GetDW(BYTE aoValue[4]) {
	DWORD dwValue = 0;
	for (int i = sizeof DWORD - 1; i >= 0; i--) {
		dwValue = (dwValue << 8) | aoValue[i];
	}
	return dwValue;
}
//
//	Endian-independent store DWORD in little-endian format.
//
void
CHeaderHeader::SetDW(BYTE aoValue[4], DWORD dwValue) {
	for (int i = 0; i < sizeof DWORD; i++) {
		aoValue[i] = (BYTE)dwValue & 0xff;
		dwValue >>= 8;
	}
}
//
//	Endian-independent store QWORD in little-endian format.
//
void
CHeaderHeader::SetQW(BYTE aoDst[8], QWORD qwValue) {
	for (int i = 0; i < sizeof qwValue; i++) {
		aoDst[i] = (BYTE)qwValue & 0xff;
		qwValue >>= 8;
	}
}
//
//	Endian-independent load QWORD
//
QWORD
CHeaderHeader::GetQW(BYTE aoSrc[8]) {
	QWORD qwValue = 0;
	for (int i = sizeof qwValue - 1; i >= 0; i--) {
		qwValue = (qwValue << 8) | aoSrc[i];
	}
	return qwValue;
}
//
//	Allocate and align (round the size upwards) of the length given.
//
void
CHeaderHeader::AllocateHeader(size_t iLen, size_t iAlign) {
	if (m_pvHeaderData != NULL) {
		delete m_pvHeaderData;
		m_pvHeaderData = NULL;
		m_iHeaderSize = 0;
	}
	m_iHeaderSize = (DWORD)((iLen + iAlign - 1) - (iLen + iAlign - 1) % iAlign);
	m_pvHeaderData = new BYTE[m_iHeaderSize];
	ASSPTR(m_pvHeaderData);

	// Ensure that any left-over space contains random junk.
	pgPRNG->RandomFill(m_pvHeaderData, m_iHeaderSize);
	return;
}
//
//	ePreamble - No special initialization.
//
CHeaderPreamble::CHeaderPreamble() : CHeaderHeader() {
	SetType(ePreamble);
	AllocateHeader(sizeof SPreamble, sizeof DWORD);
}
//
//	eVersion - Initialize with current software version etc.
//
CHeaderVersion::CHeaderVersion() : CHeaderHeader() {
	SetType(eVersion);
	AllocateHeader(sizeof SVersion, sizeof DWORD);

	Set();  // Set the actual values.
}
//
//
//
void
CHeaderVersion::Set() {
	CVersion utVersion;
	// This is actually a bit of an issue - the version fields in the header are too narrow. This especially fails for the 'Minuscule' field
	// which correspond to revision, which is typically the source code control revision number - much larger!
	((SVersion*)m_pvHeaderData)->oVersionMajor = static_cast<BYTE>(utVersion.Major());
	((SVersion*)m_pvHeaderData)->oVersionMinor = static_cast<BYTE>(utVersion.Minor());
	((SVersion*)m_pvHeaderData)->oVersionMinuscle = static_cast<BYTE>(utVersion.Minuscle());
	((SVersion*)m_pvHeaderData)->oFileVersionMajor = static_cast<BYTE>(utVersion.FileMajor());
	((SVersion*)m_pvHeaderData)->oFileVersionMinor = static_cast<BYTE>(utVersion.FileMinor());
}
//
// eKeyWrap1
//
CHeaderKeyWrap1::CHeaderKeyWrap1() : CHeaderHeader() {
	SetType(eKeyWrap1);
	AllocateHeader(sizeof SKeyWrap, sizeof DWORD);

	SKeyWrap* pSKeyWrap = (SKeyWrap*)m_pvHeaderData;
	// Initialize with value according to FIPS recommendations.
	CopyMemory(&pSKeyWrap->utKeyData[0], aoKeyWrapA, sizeof aoKeyWrapA);

	// Get the iteration count from the registry. If not there, use
	// FIPS default 6.
	DWORD dwKeyIter = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValKeyWrapIterations).GetDword(6);
	dwKeyIter = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeyWrapIterations).GetDword(dwKeyIter);
	// Ensure that we never go below 6 iterations.
	SetDW(pSKeyWrap->oIter, dwKeyIter >= 6 ? dwKeyIter : 6);
}
//
//	The IdTag
//
CHeaderIdTag::CHeaderIdTag() : CHeaderHeader() {
	SetType(eIdTag);
}
//
//	The original file times
//
CHeaderFileInfo::CHeaderFileInfo() : CHeaderHeader() {
	SetType(eFileInfo);
	AllocateHeader(sizeof SFileInfo, sizeof TBlock);
}
//
//	The original file name
//
CHeaderFileNameInfo::CHeaderFileNameInfo() : CHeaderHeader() {
	SetType(eFileNameInfo);
}
//
//	The original Unicode file name
//
CHeaderUnicodeFileNameInfo::CHeaderUnicodeFileNameInfo() : CHeaderHeader() {
	SetType(eUnicodeFileNameInfo);
}
//
//	The compression length data
//
CHeaderCompressionInfo::CHeaderCompressionInfo() : CHeaderHeader() {
	SetType(eCompressionInfo);
	AllocateHeader(sizeof SCompressionInfo, sizeof TBlock);
}
//
//  The compression flag
//
CHeaderCompressionFlag::CHeaderCompressionFlag() : CHeaderHeader() {
	SetType(eCompressionFlag);
	AllocateHeader(sizeof SCompressionFlag, sizeof TBlock);
}

//
//	The encryption data
//
CHeaderEncryptionInfo::CHeaderEncryptionInfo() : CHeaderHeader() {
	SetType(eEncryptionInfo);
	AllocateHeader(sizeof SEncryptionInfo, sizeof TBlock);
}
//
//	The actual [encrypted and/or compressed] data follows directly
//	after this header. The header also contains the length of data
//	to follow for integrity-checking purposes.
//
CHeaderData::CHeaderData() : CHeaderHeader() {
	SetType(eData);
	AllocateHeader(sizeof SData, sizeof DWORD);
}
//
//	The Headers container class, the one we actually use externally.
//
//
//	Construct an empty header set
//
CHeaders::CHeaders() {
	m_pFirst = NULL;
	m_pDataEncKey = new TKey;					// Always have room for one on the heap...
	ASSPTR(m_pDataEncKey);

	m_pIV = new TBlock;							// ...and for an IV too.
	ASSPTR(m_pIV);

	m_szFileName = NULL;
	Init();										// Make sure all required header sections are there.
}
//
//	Clean up, let the list take care of itself.
//
CHeaders::~CHeaders() {
	Clear();
	if (m_szFileName != NULL) delete m_szFileName;
	delete m_pDataEncKey;
	delete m_pIV;
}
//
//	Get HMAC value in the headers, throw an error if it is missing
//
THmac*
CHeaders::GetHMAC() {
	CHeaderPreamble* pPreamble = (CHeaderPreamble*)Find(ePreamble);
	CAssert(pPreamble != NULL).App(MSG_MISSING_SECTION, _T("Preamble")).Throw();

	return &((CHeaderPreamble::SPreamble*)pPreamble->m_pvHeaderData)->utHMAC;
}
//
//	Set calculated HMAC, create the header section if necessary
//
void
CHeaders::SetHMAC(THmac* pHMAC) {
	CHeaderPreamble* pPreamble = (CHeaderPreamble*)Find(ePreamble);
	if (pPreamble == NULL) {
		pPreamble = new CHeaderPreamble;
		ASSPTR(pPreamble);

		Add(pPreamble);
	}

	CopyMemory(
		(&((CHeaderPreamble::SPreamble*)pPreamble->m_pvHeaderData)->utHMAC),
		pHMAC,
		sizeof * pHMAC);
}
//
//	Get Major file version - if greater than our own, we are incompatible.
//
BYTE
CHeaders::GetFileVersionMajor() {
	CHeaderVersion* pVersion = (CHeaderVersion*)Find(eVersion);
	CAssert(pVersion != NULL).App(MSG_MISSING_SECTION, _T("GetFileVersionMajor")).Throw();

	return ((CHeaderVersion::SVersion*)pVersion->m_pvHeaderData)->oFileVersionMajor;
}
//
//	Get Minor file version - if greater than our own we should handle by ignoring extra data.
//	If less, we may need to take care.
//
BYTE
CHeaders::GetFileVersionMinor() {
	CHeaderVersion* pVersion = (CHeaderVersion*)Find(eVersion);
	CAssert(pVersion != NULL).App(MSG_MISSING_SECTION, _T("GetFileVersionMinor")).Throw();

	return ((CHeaderVersion::SVersion*)pVersion->m_pvHeaderData)->oFileVersionMinor;
}

//
//	Set Version, create the header section if necessary
//
void
CHeaders::SetFileVersion() {
	CHeaderVersion* pVersion = (CHeaderVersion*)Find(eVersion);
	if (pVersion == NULL) {
		pVersion = new CHeaderVersion;
		ASSPTR(pVersion);

		Add(pVersion);
	}
	else {
		// Ensure that the current version numbers are written out.
		pVersion->Set();
	}
}
//
//	Get IV, throw error if missing. The IV is loaded from the
//	encryption info block. As it is connected with a key, the
//	key must be valid.
//
TBlock*
CHeaders::GetIV() {
	CAssert(m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::GetIV [!fKeyIsValid]")).Throw();

	return m_pIV;
}
//
//	Set IV. No input argument, we generate the IV internally instead.
//
//	It is saved together with the key when wrap the key data.
//
void
CHeaders::SetIV() {
	// Generate the IV to use.
	pgPRNG->Seed(NULL, 0).RandomFill(m_pIV, sizeof * m_pIV);
}
//
//	Get the Data Enc Key used, return NULL if not set.
//
TKey*
CHeaders::GetDataEncKey() {
	return m_fKeyIsValid ? m_pDataEncKey : NULL;
}
//
//	Generate a new Data Enc Key - There must be no previous key-blocks!
//	We 'never' change the data encryption key as it may be encrypted under
//	several other key encrypting keys we do not know.
//
void
CHeaders::SetDataEncKey(TKey* pKeyEncKey) {
	CAssert(Find(eKeyWrap1) == NULL).App(MSG_INTERNAL_ERROR, _T("CHeaders::SetDataEncKey")).Throw();

	// Do this before the seeding.
	SetIV();

	// Seed the PRNG with the current entropy and the key encrypting key, being the
	// secret part required by the FIPS 186-2 PRNG.
	// Then generate the actual base Data Encrypting Key
	pgPRNG->Seed(pKeyEncKey, sizeof * pKeyEncKey).RandomFill(m_pDataEncKey, sizeof * m_pDataEncKey);

	m_fOpen = m_fKeyIsValid = TRUE;

	// Allocate and add the Key Wrap Header to the header list
	CHeaderKeyWrap1* pKeyWrap = new CHeaderKeyWrap1;
	ASSPTR(pKeyWrap);

	pKeyWrap = (CHeaderKeyWrap1*)Add(pKeyWrap);

	// Wrap it and save in the key wrap header.
	AESWrapKey(pKeyEncKey, pKeyWrap);
}
//
// Store the length of the plaintext before encryption in the encryption info header
//
void
CHeaders::SetPlainSize(QWORD qwPlain) {
	CHeaderEncryptionInfo* pEncryptionInfo = (CHeaderEncryptionInfo*)Find(eEncryptionInfo);
	if (pEncryptionInfo == NULL) {
		pEncryptionInfo = new CHeaderEncryptionInfo;
		ASSPTR(pEncryptionInfo);

		Add(pEncryptionInfo);
	}

	pEncryptionInfo->SetQW(((CHeaderEncryptionInfo::SEncryptionInfo*)pEncryptionInfo->m_pvHeaderData)->aoPlainSize, qwPlain);
}
//
// Get the length of the plaintext in the header
//
QWORD
CHeaders::GetPlainSize() {
	CHeaderEncryptionInfo* pEncryptionInfo = (CHeaderEncryptionInfo*)Find(eEncryptionInfo);
	CAssert(pEncryptionInfo != NULL).App(MSG_MISSING_SECTION, _T("GetPlainSize")).Throw();

	return pEncryptionInfo->GetQW(((CHeaderEncryptionInfo::SEncryptionInfo*)pEncryptionInfo->m_pvHeaderData)->aoPlainSize);
}
//
// Store the length of the uncompressed plaintext in the compression header
//
void
CHeaders::SetNormalSize(QWORD qwNormal) {
	CHeaderCompressionInfo* pCompressionInfo = (CHeaderCompressionInfo*)Find(eCompressionInfo);
	if (pCompressionInfo == NULL) {
		pCompressionInfo = new CHeaderCompressionInfo;
		ASSPTR(pCompressionInfo);

		Add(pCompressionInfo);
	}

	pCompressionInfo->SetQW(((CHeaderCompressionInfo::SCompressionInfo*)pCompressionInfo->m_pvHeaderData)->aoNormalSize, qwNormal);
}
//
// Get the length of the uncompressed plaintext from the compression header in memory
//
QWORD
CHeaders::GetNormalSize() {
	CHeaderCompressionInfo* pCompressionInfo = (CHeaderCompressionInfo*)Find(eCompressionInfo);
	CAssert(pCompressionInfo != NULL).App(MSG_MISSING_SECTION, _T("GetNormalSize")).Throw();

	return pCompressionInfo->GetQW(((CHeaderCompressionInfo::SCompressionInfo*)pCompressionInfo->m_pvHeaderData)->aoNormalSize);
}
//
// TRUE if the compression headers are marked special.
//
// We do it this way, instead of just leaving them out,
// as we want to disclose as little as possible about
// a file, including whether it is compressed or not.
// Doing it this way, an attacker does not even know
// if the original file was compressed or not.
//
BOOL
CHeaders::IsCompressed() {
	CHeaderCompressionFlag* pCompressionFlag = (CHeaderCompressionFlag*)Find(eCompressionFlag);
	// If header is not there, it's an old file with compression.
	if (pCompressionFlag == NULL) {
		return TRUE;
	}
	return pCompressionFlag->GetDW(((CHeaderCompressionFlag::SCompressionFlag*)pCompressionFlag->m_pvHeaderData)->aoCompFlag);
}
//
//  Set true or false depending on whether compression is used or not.
//
void
CHeaders::SetCompressionFlag(BOOL fCompFlag) {
	CHeaderCompressionFlag* pCompressionFlag = (CHeaderCompressionFlag*)Find(eCompressionFlag);
	if (pCompressionFlag == NULL) {
		pCompressionFlag = new CHeaderCompressionFlag;
		ASSPTR(pCompressionFlag);

		Add(pCompressionFlag);
	}

	pCompressionFlag->SetDW(((CHeaderCompressionFlag::SCompressionFlag*)pCompressionFlag->m_pvHeaderData)->aoCompFlag, fCompFlag);
}
//
//	Set the exact size of the output data
//
void
CHeaders::SetDataSize(QWORD qwEncrypted) {
	CHeaderData* pData = (CHeaderData*)Find(eData);
	if (pData == NULL) {
		pData = new CHeaderData;
		ASSPTR(pData);

		Add(pData);
	}

	pData->SetQW(((CHeaderData::SData*)pData->m_pvHeaderData)->aoDataSize, qwEncrypted);
}
//
//	Get the exact size of the output data
//
QWORD
CHeaders::GetDataSize() {
	CHeaderData* pData = (CHeaderData*)Find(eData);
	CAssert(pData != NULL).App(MSG_MISSING_SECTION, _T("GetDataSize")).Throw();

	return pData->GetQW(((CHeaderData::SData*)pData->m_pvHeaderData)->aoDataSize);
}
//
// Store the time the plain text was last written to.
//
void
CHeaders::SetFileTimes(SFileTimes* pFileTimes) {
	CHeaderFileInfo* pFileInfo = (CHeaderFileInfo*)Find(eFileInfo);
	if (pFileInfo == NULL) {
		pFileInfo = new CHeaderFileInfo;
		ASSPTR(pFileInfo);

		Add(pFileInfo);
	}

	// We know that FILETIME is a 64-bit integer representing # 100-nanoseconds since Jan 1, 1601.
	pFileInfo->SetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[0], *(QWORD*)&pFileTimes->CreationTime);
	pFileInfo->SetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[8], *(QWORD*)&pFileTimes->LastAccessTime);
	pFileInfo->SetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[16], *(QWORD*)&pFileTimes->LastWriteTime);
}
//
// Get the time the plain text was last written to.
//
SFileTimes*
CHeaders::GetFileTimes() {
	CHeaderFileInfo* pFileInfo = (CHeaderFileInfo*)Find(eFileInfo);
	CAssert(pFileInfo != NULL).App(MSG_MISSING_SECTION, _T("GetFileTimes")).Throw();

	// We know that FILETIME is a 64-bit integer representing # 100-nanoseconds since Jan 1, 1601.
	*(QWORD*)&m_utFileTimes.CreationTime = pFileInfo->GetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[0]);
	*(QWORD*)&m_utFileTimes.LastAccessTime = pFileInfo->GetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[8]);
	*(QWORD*)&m_utFileTimes.LastWriteTime = pFileInfo->GetQW(&((CHeaderFileInfo::SFileInfo*)pFileInfo->m_pvHeaderData)->aoFileTimes[16]);
	return &m_utFileTimes;
}

// Set an IdTag
void
CHeaders::SetIdTag(const wchar_t* szIdTag) {
	CHeaderIdTag* pIdTag = (CHeaderIdTag*)Find(eIdTag);
	if (pIdTag == NULL) {
		pIdTag = new CHeaderIdTag;
		ASSPTR(pIdTag);

		Add(pIdTag);
	}

	// Xecrets File Classic was originally not a Unicode app, so header data is stored in
	// Ansi Code Page. Since we're now Unicode, we'll convert the incoming Unicode
	// text to ACP. It's simply not worth it to store it in both Unicode and Ansi
	// for backwards compatiblity. It's simply easier to say that comments are only
	// stored in Ansi for now.
	// We need to special alignment here.
	std::string ansiIdTag = axpl::ws2s(wstring(szIdTag));
	size_t ccIdTag = 1 + ansiIdTag.length();
	pIdTag->AllocateHeader(ccIdTag, 1);
	strcpy_s((LPSTR)pIdTag->m_pvHeaderData, ccIdTag, ansiIdTag.c_str());
}
//
//	Get an IdTag, stored in ACP.
//
//	The returned string, if any, needs deletion by the caller!
//
wchar_t*
CHeaders::GetIdTag() {
	CHeaderIdTag* pIdTag = (CHeaderIdTag*)Find(eIdTag);
	if (pIdTag == NULL) {
		return NULL;
	}
	std::wstring wideIdTag = axpl::s2ws(string(reinterpret_cast<char*>(pIdTag->m_pvHeaderData)));
	return CopySz(wideIdTag.c_str());
}

//
//	Compare the stored last write time, with a given time. The operation is equivalent to
//	this->m_FileTimes.LastWriteTime - *pLastWriteTime
//
//	i.e. < 0 means that the given time happend after our stored time.
//
int
CHeaders::CompareFileTime(FILETIME* pLastWriteTime) {
	return ::CompareFileTime(&m_utFileTimes.LastWriteTime, pLastWriteTime);
}

//
// Get original Unicode or fallback to ANSI, file name. Unicode support added 1.6.3.3
//
LPTSTR
CHeaders::GetFileName() {
	if (m_szFileName != NULL) {
		delete[] m_szFileName;
		m_szFileName = NULL;
	}

	axpl::ttstring tFileName;

	CHeaderUnicodeFileNameInfo* pUnicodeFileName = (CHeaderUnicodeFileNameInfo*)Find(eUnicodeFileNameInfo);
	// Check if we found a Unicode file name in there...
	if (pUnicodeFileName != NULL) {
		// ...whopee - we did!
		tFileName = axpl::w2t((wchar_t*)pUnicodeFileName->m_pvHeaderData);
	}
	else {
		CHeaderFileNameInfo* pFileName = (CHeaderFileNameInfo*)Find(eFileNameInfo);
		CAssert(pFileName != NULL).App(MSG_MISSING_SECTION, _T("GetFileName")).Throw();

		tFileName = axpl::s2t((char*)pFileName->m_pvHeaderData);
	}

	size_t ccFileName = 1 + _tcslen(tFileName.c_str());
	m_szFileName = new TCHAR[ccFileName];
	ASSPTR(m_szFileName);

	_tcscpy_s(m_szFileName, ccFileName, tFileName.c_str());
	return m_szFileName;
}

//
// Set the original ANSI and Unicode name of the file.
//
void
CHeaders::SetFileName(LPCTSTR szFileName) {
	// As of 1.6.3.3 we are fully Unicode enabled, and store the original name as it is - in Unicode.
	CHeaderUnicodeFileNameInfo* pUnicodeFileName = (CHeaderUnicodeFileNameInfo*)Find(eUnicodeFileNameInfo);
	if (pUnicodeFileName == NULL) {
		pUnicodeFileName = new CHeaderUnicodeFileNameInfo;
		ASSPTR(pUnicodeFileName);

		Add(pUnicodeFileName);
	}

	// Ensure that the header is a number of TBlocks long.
	std::wstring wUnicodeFileName = axpl::t2ws(szFileName);
	size_t ccUnicodeFileName = 1 + wUnicodeFileName.length();
	pUnicodeFileName->AllocateHeader(ccUnicodeFileName * sizeof(wchar_t), sizeof TBlock);
	wcscpy_s((wchar_t*)pUnicodeFileName->m_pvHeaderData, ccUnicodeFileName, wUnicodeFileName.c_str());

	// Now set the fallback backwards compatible Ansi version of the file name
	CHeaderFileNameInfo* pFileName = (CHeaderFileNameInfo*)Find(eFileNameInfo);
	if (pFileName == NULL) {
		pFileName = new CHeaderFileNameInfo;
		ASSPTR(pFileName);

		Add(pFileName);
	}

	// Ensure that the header is a number of TBlocks long.
	std::string sFileName = axpl::t2s(szFileName);
	size_t ccFileName = 1 + strlen(sFileName.c_str());
	pFileName->AllocateHeader(ccFileName, sizeof TBlock);
	strcpy_s((char*)pFileName->m_pvHeaderData, ccFileName, sFileName.c_str());
}
//
// Where to start HMAC'ing (after Preamble).
//
DWORD
CHeaders::OffsetToHMAC() {
	CHeaderPreamble* pPreamble = (CHeaderPreamble*)Find(ePreamble);
	CAssert(pPreamble != NULL).App(MSG_MISSING_SECTION, _T("Preamble")).Throw();

	// Size of Preamble plus the GUID header.
	return pPreamble->Size() + sizeof guidAxCryptFileId;
}
//
//	Load from opened file - verify GUID & Header structure. Throw an exception on error
//
CHeaders&
CHeaders::Load(CFileIO& rFile) {
	VerifyStructure(rFile);

	// The file must begin with the preamble header, begin with rewind,
	// skipping the GUID.
	rFile.SetFilePointer(sizeof guidAxCryptFileId);

	// If, by chance, we have data, delete it properly first.
	Clear();

	// This code will definitely 'leak'..
	HEAP_CHECK_BEGIN(_T("CHeaders::Load()"), TRUE)
		TBlockType eHeaderType = (TBlockType)0;
	// While we have not read the data header.
	while (eHeaderType != eData) {
		switch (eHeaderType = CHeaderHeader::PeekType(rFile)) {
		case ePreamble:
			// Ensure that preamble starts the headers.
			CAssert(m_pFirst == NULL).App(MSG_PREAMBLE_NOT_FIRST).Throw();

			// Allocate the first header.
			(void)Add(new CHeaderPreamble)->Get(rFile); // Add checks the pointer

			// We can't check the HMAC yet! Need the Key Encrypting Key for that.
			break;
		case eVersion:
			// Only one eVersion allowed.
			CAssert(Find(eVersion) == NULL).App(MSG_VERSION_TWICE).Throw();

			(void)Add(new CHeaderVersion)->Get(rFile); // Add checks the pointer

			// Check that the file version is down-compatible to our level.
			CAssert(GetFileVersionMajor() <= CVersion().FileMajor()).App(MSG_FILE_VERSION).Throw();
			break;
		case eKeyWrap1:
			// We support multiple wrappings of the Data Encrypting Key
			(void)Add(new CHeaderKeyWrap1)->Get(rFile); // Add checks the pointer
			break;
		case eIdTag:
			// Only one eIdTag allowed
			CAssert(Find(eIdTag) == NULL).App(ERR_HEADER_TWICE, _T("IdTag")).Throw();

			(void)Add(new CHeaderIdTag)->Get(rFile); // Add checks the pointer
			break;
		case eFileInfo:
			// Only one eFileInfo allowed.
			CAssert(Find(eFileInfo) == NULL).App(ERR_HEADER_TWICE, _T("FileInfo")).Throw();

			(void)Add(new CHeaderFileInfo)->Get(rFile); // Add checks the pointer
			break;
		case eFileNameInfo:
			// Only one eFileName allowed.
			CAssert(Find(eFileNameInfo) == NULL).App(ERR_HEADER_TWICE, _T("FileNameInfo")).Throw();

			(void)Add(new CHeaderFileNameInfo)->Get(rFile); // Add checks the pointer
			break;
		case eUnicodeFileNameInfo:
			// Only one eUnicodeFileName allowed.
			CAssert(Find(eUnicodeFileNameInfo) == NULL).App(ERR_HEADER_TWICE, _T("UnicodeFileNameInfo")).Throw();

			(void)Add(new CHeaderUnicodeFileNameInfo)->Get(rFile); // Add checks the pointer
			break;
		case eEncryptionInfo:
			// Only one eEncryptionInfo allowed.
			CAssert(Find(eEncryptionInfo) == NULL).App(ERR_HEADER_TWICE, _T("EncryptionInfo")).Throw();

			(void)Add(new CHeaderEncryptionInfo)->Get(rFile); // Add checks the pointer
			break;
		case eCompressionInfo:
			// Only one eCompressionInfo allowed.
			CAssert(Find(eCompressionInfo) == NULL).App(ERR_HEADER_TWICE, _T("CompressionInfo")).Throw();

			(void)Add(new CHeaderCompressionInfo)->Get(rFile); // Add checks the pointer
			break;
		case eCompressionFlag:
			// Only one eCompressionFlag allowed.
			CAssert(Find(eCompressionFlag) == NULL).App(ERR_HEADER_TWICE, _T("CompressionFlag")).Throw();

			(void)Add(new CHeaderCompressionFlag)->Get(rFile); // Add checks the pointer
			break;
		case eData:
			// The while terminates on eData, so by definition this must be the first
			// therefore we need no check.
			(void)Add(new CHeaderData)->Get(rFile); // Add checks the pointer
			break;

		default:
			// Unknown header types are simply skipped
			CHeaderUnknown().Get(rFile);
			break;
		}
	}

	// Calculate the real size of the headers, including skipped, unknown ones and the magic guid at the start.
	m_dwSizeOnFile = (DWORD)rFile.GetFilePointer();   // We have a limit on header-size to 2Gb.

	try {
		// Ensure that we there is no extra data and that the file is not truncated.
		CAssert((m_dwSizeOnFile + GetDataSize()) == rFile.m_qwFileSize).App(MSG_FILE_LENGTH).Throw();
	}
	catch (TAssert utErr) {
		ConditionalThrow(utErr, MSG_FILE_LENGTH);
	}

	// Keep track of the original encrypted file name for messages.
	m_EncryptedFileName.Set(rFile.GetFileName());

	return *this;
	HEAP_CHECK_END
}
//
// Verify correct key, and decrypt etc.
//
BOOL
CHeaders::Open(TKey* pKeyEncKey) {
	// Internal sequence error if we attempt to open already open headers.
	CAssert(!m_fOpen).App(MSG_INTERNAL_ERROR, _T("CHeaders::Open [fOpen]")).Throw();
	CAssert(!m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::Open [fKeyIsValid]")).Throw();

	// For all Key Enc Key-headers, try to see if we have a match.
	for (CHeaderHeader* pHeader = Find(eKeyWrap1); (pHeader != NULL) && (pHeader->GetType() == eKeyWrap1); pHeader = pHeader->m_pNext) {
		// Try to unwrap it.
		if (UnAESWrapKey(pKeyEncKey, (CHeaderKeyWrap1*)pHeader)) {
			break;
		}
	}
	//	If we did get a valid key, proceed to decrypt encrypted headers.
	if (m_fKeyIsValid) {
		DecryptHeaders();

		// ...Then get the IV into memory.
		CHeaderEncryptionInfo* pHeader = (CHeaderEncryptionInfo*)Find(eEncryptionInfo);
		CAssert(pHeader != NULL).App(MSG_MISSING_SECTION, _T("CHeaders::UnAESWrapKey")).Throw();
		CopyMemory(m_pIV, &((CHeaderEncryptionInfo::SEncryptionInfo*)pHeader->m_pvHeaderData)->utIV, sizeof * m_pIV);
	}
	return m_fOpen;
}
//
//	Re-open using existing key
//
BOOL
CHeaders::ReOpen() {
	// Internal sequence error if we attempt to open already open headers.
	CAssert(!m_fOpen).App(MSG_INTERNAL_ERROR, _T("CHeaders::ReOpen [m_fOpen]")).Throw();
	CAssert(m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::ReOpen [m_fKeyIsValid]")).Throw();

	DecryptHeaders();
	return m_fOpen;
}
void
CHeaders::WrapKeyData(TKey* pKeyEncKey) {
	CAssert(m_fOpen).App(MSG_INTERNAL_ERROR, _T("CHeaders::Wrap [m_fOpen]")).Throw();
	CAssert(m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::Wrap [m_fKeyIsValid]")).Throw();

	// Now get hold of the key wrap header
	CHeaderKeyWrap1* pKeyWrap = (CHeaderKeyWrap1*)Find(eKeyWrap1);
	CAssert(pKeyWrap != NULL).App(MSG_MISSING_SECTION, _T("CHeaders::WrapKeyData")).Throw();

	// And do the wrapping of the key data.
	AESWrapKey(pKeyEncKey, pKeyWrap);
}
//
// Encrypt headers etc.
//
void
CHeaders::Close() {
	// Internal sequence error if we attempt to close non-open headers.
	CAssert(m_fOpen).App(MSG_INTERNAL_ERROR, _T("CHeaders::Close [fOpen]")).Throw();
	CAssert(m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::Close [fKeyIsValid]")).Throw();

	CHeaderEncryptionInfo* pHeader = (CHeaderEncryptionInfo*)Find(eEncryptionInfo);
	if (pHeader == NULL) {
		pHeader = (CHeaderEncryptionInfo*)Add(new CHeaderEncryptionInfo); // Add checks the pointer
	}
	CopyMemory(&((CHeaderEncryptionInfo::SEncryptionInfo*)pHeader->m_pvHeaderData)->utIV, m_pIV, sizeof * m_pIV);
	EncryptHeaders();
}
//
// Write them to the file
//
void
CHeaders::Save(CFileIO& rFile, HWND hProgressWnd, LONGLONG llOffset) {
	// Update version if different from the one loaded.
	SetFileVersion();

	// Ensure there is no open file-map view, as we're now starting to write data using
	// file io. This should be cleaned up in the future. 1.4d1.3
	//rFile.CloseView();

	// Save headers so we can calculate the HMAC and then resave.
	rFile.SetFilePointer(llOffset);

	// Start by writing the GUID at the start of the file.
	size_t cb = sizeof guidAxCryptFileId;
	rFile.WriteData(&guidAxCryptFileId, &cb);
	CAssert(cb == sizeof guidAxCryptFileId).App(MSG_INTERNAL_ERROR, _T("CHeaders::Save [Short write]")).Throw();

	m_pFirst->PutAll(rFile);

	// Get the subkey and initialize the HMAC-object
	CHmac utFileHMAC(GetDataEncKey(), hProgressWnd);

	// Skip the parts of the file that should not be included in the HMAC
	rFile.SetFilePointer(llOffset + OffsetToHMAC());

	// Do the job
	utFileHMAC.XformData(rFile, CFileDummy());

	// Save the HMAC in the headers structure.
	SetHMAC(utFileHMAC.GetHMAC());

	rFile.SetFilePointer(llOffset + sizeof guidAxCryptFileId);
	m_pFirst->PutAll(rFile);
}
//
//	Init, ensuring that all mandatory headers are present.
//
CHeaders&
CHeaders::Init() {
	Clear();
	// These sections need always be in place for a brand-new header.
	// It is important for the size-calculation that these are put
	// in place early too.
	Add(new CHeaderPreamble); // Add checks the pointer
	Add(new CHeaderVersion); // Add checks the pointer
	Add(new CHeaderData); // Add checks the pointer
	return *this;
}
//
//	Clear all data
//
CHeaders&
CHeaders::Clear() {
	m_fOpen = m_fKeyIsValid = FALSE;
	// We always keep room for the data enc key, until destruction
	ZeroMemory(m_pDataEncKey, sizeof * m_pDataEncKey);

	if (m_pFirst != NULL) {
		delete m_pFirst;
		m_pFirst = NULL;
	}
	return *this;
}
//
//	Total size of all headers loaded in memory.
//
DWORD
CHeaders::SizeInMemory() {
	// Dynamic headers plus length of GUID.
	return m_pFirst->SizeAll() + sizeof guidAxCryptFileId;
}
//
//	Return the length of the headers found on disk
//
DWORD
CHeaders::SizeOnFile() {
	return m_dwSizeOnFile;
}
//
//	Encrypt or Decrypt headers that should be, according to param
//
void
CHeaders::EncDecHelper(CAes::etDirection eDirection) {
	// Key must be valid...
	CAssert(m_fKeyIsValid).App(MSG_INTERNAL_ERROR, _T("CHeaders::EncDecHelper")).Throw();

	// For all headers...
	for (CHeaderHeader* pHeader = m_pFirst; pHeader != NULL; pHeader = pHeader->m_pNext) {
		// If this is an encrypted type header
		if (pHeader->m_utHeader.oType & eEncryptedFlag) {
			// Initialize an AES structure with the Data Encrypting Key and the proper direction.
			CAes utAesContext(CSubKey().Set(m_pDataEncKey, CSubKey::eHeaders).Get(), CAes::eCBC, eDirection);

			// Encrypt/Decrypt the block with default IV of zero.
			utAesContext.Xblock((TBlock*)pHeader->m_pvHeaderData, (TBlock*)pHeader->m_pvHeaderData, pHeader->m_iHeaderSize / sizeof TBlock);
		}
	}
}
//
//	Try to unwrap a wrapped key. Return TRUE and set
//	m_fValidKey m_pDataEncKey and m_pIV if ok.
//
BOOL
CHeaders::UnAESWrapKey(TKey* pKeyEncKey, CHeaderKeyWrap1* pKeyWrap) {
	CHeaderKeyWrap1::SKeyWrap* pSKeyWrap = (CHeaderKeyWrap1::SKeyWrap*)pKeyWrap->m_pvHeaderData;

	CAesWrap utAesWrap(CHeaderHeader::GetDW(pSKeyWrap->oIter), sizeof TKey);

	//
	// The following is just because of a bug in 1.1 and earlier, where we only used 4 bytes
	// of the salt and key... To maintain compatibility, we check the header version, and if
	// necessary clear all but the first 4 bytes - this will have the desired effect.
	//
	//  This happened because 'sizeof pSaltedKeyEncKey' was used as the length specifier
	//  for a call to XorMemory, instead of 'sizeof *pSaltedKeyEncKey'... Mega :-(. Even
	//  worse, the same error was replicated to the wrapping function, probably because of
	//  cut and paste, which caused the transformation to succeed anyway, otherwise it
	//  would have been detected at once. Giga sigh. Well, it's fixed now.
	//
	if (GetFileVersionMajor() <= 1) {
		CPtrTo<TKey> pBadKey = new TKey;
		ASSPTR(pBadKey);

		CPtrTo<TKey> pBadSalt = new TKey;
		ASSPTR(pBadSalt);

		ZeroMemory(pBadKey, sizeof * pBadKey);
		CopyMemory(pBadKey, pKeyEncKey, 4);

		ZeroMemory(pBadSalt, sizeof * pBadSalt);
		CopyMemory(pBadSalt, pSKeyWrap->oSalt, 4);

		if (m_fKeyIsValid = utAesWrap.UnWrap(pBadKey, pSKeyWrap->utKeyData, pBadSalt)) {
			CMessage().AppMsg(WRN_REENCRYPT, NULL, m_EncryptedFileName.Get()).ShowWarning();
		}
	}
	else {
		m_fKeyIsValid = utAesWrap.UnWrap(pKeyEncKey, pSKeyWrap->utKeyData, pSKeyWrap->oSalt);
	}
	if (m_fKeyIsValid) {
		// Copy the correct data encrypting key.
		CopyMemory(m_pDataEncKey, utAesWrap.GetKey(), sizeof * m_pDataEncKey);

		// And copy the data to the header.
		CopyMemory(pSKeyWrap->utKeyData, utAesWrap.GetWrap(), sizeof pSKeyWrap->utKeyData);
	}
	return m_fKeyIsValid;
}
//
//	Wrap key with KEK using AES FIPS recommendations.
//
//	A Salt is added to the Key Encrypting Key before wrapping, according to the
//	ideas and thoughts presented in RSA Laboratories PKCS#5 v2.0. This prevents
//	attacks based on precomputing.
//
void
CHeaders::AESWrapKey(TKey* pKeyEncKey, CHeaderKeyWrap1* pKeyWrap) {
	CHeaderKeyWrap1::SKeyWrap* pSKeyWrap = (CHeaderKeyWrap1::SKeyWrap*)pKeyWrap->m_pvHeaderData;

	// First generate a salt
	pgPRNG->RandomFill(pSKeyWrap->oSalt, sizeof pSKeyWrap->oSalt);

	// Do the key wrap
	CAesWrap utAesWrap(CHeaderHeader::GetDW(pSKeyWrap->oIter), sizeof TKey);
	utAesWrap.Wrap(pKeyEncKey, m_pDataEncKey, pSKeyWrap->oSalt);

	// Get and store the result
	CopyMemory(pSKeyWrap->utKeyData, utAesWrap.GetWrap(), sizeof pSKeyWrap->utKeyData);
}
//
//	Do a scan through the file and verify it's general structure.
//	Throw an error if anything is wrong. The purpose is to ensure
//	that Load() can read the file without failing, except of course
//	if it detetects semantic errors. This code looks for syntactic
//	errors in the file, so to speak.
//
//	Do the following checks:
//
//	1 - GUID in the right place (start of file) -> Error if not.
//	2 - Follow the chain of headers, checking for illegal length values etc.
//
void
CHeaders::VerifyStructure(CFileIO& rFile) {
	// First check the GUID
	BYTE aoGUID[16];

	rFile.SetFilePointer(0);

	size_t cb = sizeof aoGUID;
	rFile.ReadData(aoGUID, &cb);
	CAssert(cb == sizeof aoGUID).App(MSG_INVALID_GUID).Throw();
	CAssert(memcmp(aoGUID, &guidAxCryptFileId, sizeof guidAxCryptFileId) == 0).App(MSG_INVALID_GUID).Throw();

	struct CHeaderHeader::SHeader utSHeader;
	DWORD dwHeaderLen = sizeof utSHeader;

	try {
		do {
			cb = sizeof utSHeader;
			rFile.ReadData(&utSHeader, &cb);
			CAssert(cb == sizeof utSHeader).App(MSG_FILE_FORMAT).Throw();

			dwHeaderLen = CHeaderHeader::GetDW(utSHeader.aoLength);
			CAssert(dwHeaderLen >= sizeof utSHeader).App(MSG_FILE_FORMAT).Throw();

			CAssert((QWORD)(rFile.GetFilePointer() + dwHeaderLen - sizeof utSHeader) <= rFile.m_qwFileSize).App(MSG_FILE_FORMAT).Throw();

			rFile.SetFilePointer(rFile.GetFilePointer() + dwHeaderLen - sizeof utSHeader);
		} while (utSHeader.oType != eData);

		struct CHeaderData::SData utSData;

		// Go back the length of the length field in the CHeaderData section.
		rFile.SetFilePointer(rFile.GetFilePointer() - sizeof utSData);

		// Get the length field from the eData section
		cb = sizeof utSData;
		rFile.ReadData(&utSData, &cb);
		CAssert(cb == sizeof utSData).App(MSG_FILE_FORMAT).Throw();

		CAssert((rFile.GetFilePointer() + CHeaderHeader::GetQW(utSData.aoDataSize)) == rFile.m_qwFileSize).App(MSG_FILE_FORMAT).Throw();
	}
	catch (TAssert utErr) {
		ConditionalThrow(utErr, MSG_FILE_FORMAT);
	}
}
//
//	Encrypt headers using data here.
//
void
CHeaders::DecryptHeaders() {
	EncDecHelper(CAes::eDecrypt);
	m_fOpen = TRUE;
}
//
//	Decrypt headers using data here.
//
void
CHeaders::EncryptHeaders() {
	EncDecHelper(CAes::eEncrypt);
	m_fOpen = FALSE;
}
//
//	Find first occurrence if any of eType, or return NULL
//
CHeaderHeader*
CHeaders::Find(TBlockType eType) {
	for (CHeaderHeader* pHeader = m_pFirst; pHeader != NULL; pHeader = pHeader->m_pNext) {
		if (pHeader->m_utHeader.oType == (BYTE)eType) return pHeader;
	}
	return NULL;
}
//
//	Unconditionally add a section
//
CHeaderHeader*
CHeaders::Add(void* pNewHeader) {
	ASSPTR(pNewHeader);

	//	if m_pFirst is NULL -> Always insert at front of course.
	//	if new header is ePreamble, force it to the head.
	//	if new header is eData, force to the tail.
	CHeaderHeader** ppInsertAfter = &m_pFirst;
	if (m_pFirst != NULL) {
		if (((CHeaderHeader*)pNewHeader)->GetType() != ePreamble) {
			ppInsertAfter = &((*ppInsertAfter)->m_pNext);
			if (((CHeaderHeader*)pNewHeader)->GetType() == eData) {
				while ((*ppInsertAfter) != NULL) {
					ppInsertAfter = &((*ppInsertAfter)->m_pNext);
				}
			}
		}
	}
	((CHeaderHeader*)pNewHeader)->m_pNext = *ppInsertAfter;
	return *ppInsertAfter = (CHeaderHeader*)pNewHeader;
}
//
// Remove a header from the chain.
//
void CHeaders::Remove(void* pHeader) {
	CAssert(pHeader != NULL).App(MSG_INTERNAL_ERROR, _T("CHeaders::Remove() [1]")).Throw();
	CHeaderHeader** ppPrevious = &m_pFirst, * pCurrent = m_pFirst;

	while (pCurrent != NULL) {
		if (pCurrent == pHeader) {
			*ppPrevious = pCurrent->m_pNext;
			pCurrent->m_pNext = NULL;   // delete must not delete rest of list.
			delete pCurrent;
			return;
		}
		ppPrevious = &pCurrent->m_pNext;
		pCurrent = pCurrent->m_pNext;
	}

	// We should _never_ get here!
	CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CHeaders::Remove() [2]")).Throw();
}