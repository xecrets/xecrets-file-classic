#ifndef CXECRETSFILEMETA_H
#define CXECRETSFILEMETA_H
/*! \file
	\brief CXecretsFileMeta.h - Handle Xecrets File meta information in headers

	@(#) $Id$

	CXecretsFileMeta.h - Handle Xecrets File meta information in headers

	Copyright (C) 2005-2020 Svante Seleborg/Axantum Software AB, All rights reserved.

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
*/

#include <memory>
#include <list>

extern "C" {
#include "XecretsFileLib.h"
}
#include "BlockTypes.h"
#include "CXecretsFileAES.h"
#include "CXecretsFileLibMisc.h"

#include "Assert.h"
#define ASSERT_FILE "CXecretsFileMeta.h"

//
// Ensure the correct and expected structures regardless of optimizations.
//
#pragma pack(push)
#pragma pack(1)

namespace axcl {
	/// \brief Xecrets File Header Type Codes.
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

	/// \brief Exactly one meta section from an Xecrets File-formated file stream.
	class CMetaSection {
		TBlockType m_eType;                     ///< The type of the section, defined by TBlockType
		size_t m_cbLen;                         ///< The total length of m_pData (excluding type byte)
		unsigned char* m_pData;                 ///< The raw data, excluding type byte

		/// \brief Assignment by copying of components making up a section
		/// \param eType The section type
		/// \param pData Pointer to the data block of the section
		/// \param cbLen The length of pData
		void CopyAssign(TBlockType eType, unsigned char* pData, size_t cbLen) {
			m_eType = eType;
			delete[] m_pData;
			if (((m_cbLen = cbLen) != 0) && pData) {
				m_pData = new unsigned char[m_cbLen];
				ASSPTR(m_pData);
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
		/// \param pData Pointer to the data block of the section. Must be allocated as unsigned char *
		/// \param cbLen The length of pData
		CMetaSection(TBlockType eType = eNone, unsigned char* pData = NULL, size_t cbLen = 0) {
			m_eType = eType;
			m_pData = pData;
			m_cbLen = cbLen;
		}

		/// \brief A proper copy-constructor
		/// \see CopyAssign
		CMetaSection(const CMetaSection& rhs) {
			m_pData = NULL;
			CopyAssign(rhs.m_eType, rhs.m_pData, rhs.m_cbLen);
		}

		/// \brief delete the data buffer
		~CMetaSection() {
			delete[] m_pData;
			m_pData = NULL;
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

	/// \brief Manage the meta information of an Xecrets File stream.
	///
	/// The base class is a std::list of CMetaSection. This is where
	/// we define the various instances of CMetaSection in detail,
	/// and interpret them.
	class CXecretsFileMeta : public std::list<CMetaSection> {
		/// \brief The file version we understand/generate.
	protected:
		/// TODO: For the next file version revision, fix:
		/// Streamability - There should never be a need for a rewind during read or write
		/// Include software name, not just software version in the version header.
		/// Store file names as Unicode, not Ansi.
		/// Take care of problems (if any) with Passphrases in Unicode. Possibly try decryption with both versions?
		/// HMAC should not need recalculation for reencryption under new KEK, i.e. the KeyWrap should not be HMAC'd.
		/// The HMAC should not need two passes over the data
		/// Why is only the plain text after compression stored? This is only partially useful.
		const static int m_iFileVersionMajor = 3;
		const static int m_iFileVersionMinor = 2;

	private:
		AXCL_PARAM* m_pParam;                   ///< The caller parameter block
		int m_iKeyIndex;                        ///< The key we are using

	protected:
		axcl::TBlock m_IV;                      ///< IV for CBC decryption.
		size_t m_cbOffsetHMAC;                  ///< Offset in stream to data to HMAC
		size_t m_cbOffsetData;                  ///< Offset in stream to actual data to decrypt.
		bool m_fKeyIsValid;                     ///< true if we have a valid key
		axcl::tstring m_sError;                 ///< An error string
		axcl::CXecretsFileAESWrap m_AesWrap;        ///< Helper to unwrap the key after user entry of passphrase

		/// \brief The common header of all sections
	public:
		struct SHeader {
			axcl::byte aoLength[4];             ///< Total length of header section
			axcl::byte oType;                   ///< Cast to TBlockType as appropriate.
		} m_utHeader;

	protected:
		/// \brief Describe an ePreamble section
		struct SPreamble {
			THmac utHMAC;                       ///< HMAC-SHA1-128 of header and data excl. preamble.
		};

		/// \brief Describe a eVersion section
	protected:
		struct SVersion {
			axcl::byte oFileVersionMajor;       ///< FileMajor - Older versions cannot not read the format.
			axcl::byte oFileVersionMinor;       ///< FileMinor - Older versions can read the format, but will not retain on save.
			axcl::byte oVersionMajor;           ///< Major - New release, major functionality change.
			axcl::byte oVersionMinor;           ///< Minor - Changes, but no big deal.
			axcl::byte oVersionMinuscle;        ///< Minuscle - bugfix.
		};

		/// \brief Describe an eKeyWrap1 section, a standard 128-bit AES key.
	protected:
		struct SKeyWrap1 {
			axcl::byte utKeyData[1 + sizeof axcl::TKey / 8][8]; ///< The Key Data (A + DEK).
			axcl::byte oSalt[16];                     ///< Salt, xor'ed with KEK before wrap/unwrap.
			axcl::byte oIter[4];                      ///< Custom number of iterations for work factor increase
		};

		/// \brief Describe an EncryptionInfo section.
		///
		/// This is where we keep Initializing Vector and the size
		/// of the plain text, excluding padding (but it might be compressed etc).
	protected:
		struct SEncryptionInfo {
			axcl::byte aoPlainSize[8];    ///< The size of the plain text (it may still be compressed!)
			axcl::TBlock utIV;            ///< The IV used for CBC encryption.
		};

		/// \brief Tell if compression is applied to the stream
	protected:
		struct SCompressionFlag {
			axcl::byte aoCompFlag[sizeof axcl::uint32];///< TRUE if compression was used.
		};

	protected:
		/// \brief Additional info about the size of the uncompressed data
		struct SCompressionInfo {
			axcl::byte aoNormalSize[8];         ///< The size of the uncompressed data
		};

		/// \brief The original file name in Ansio
	protected:
		struct SFileNameInfo {
			char szFileName[1];                 ///< Actual storage is reserved in runtime
		};

		/// \brief The original file name in Unicode
	protected:
		struct SUnicodeFileNameInfo {
			wchar_t wzFileName[1];              ///< Actual storage is reserved in runtime
		};

		/// \brief The actual data follows....
	protected:
		struct SData {
			axcl::byte aoDataSize[8];           ///< The size of the possibly padded/encrypted/compressed data
		};

		/// \brief The file modification and access times of the original encrypted file
	protected:
		struct SFileTimes {
			AXCL_FILETIME CreationTime;         ///< When the file is created
			AXCL_FILETIME LastAccessTime;       ///< When the file most recently was accessed
			AXCL_FILETIME LastWriteTime;        ///< When the file most recently was updated
		};

		/// \brief The section with the file modification times of the original file
	protected:
		struct SFileInfo {
			axcl::byte aoFileTimes[sizeof SFileTimes];///< The various times associated with the file
		};

	protected:
		/// \brief Get a meta data section
		///
		/// Get the raw data from a meta section, decrypt if necessary.
		/// Delete the pointer after use.
		/// \param eType The type of data section to get the raw data for
		/// \param pcb A pointer to a size_t where the size is placed. May be NULL. Only updated if data is found.
		template<class T> T* GetMetaData(TBlockType eType, size_t* pcb = NULL) {
			iterator i = FindType(eType);
			if (i == end()) {
				return NULL;
			}

			unsigned char* p = new unsigned char[i->Len()];
			if (!p) return NULL;
			if (pcb) *pcb = i->Len();

			memcpy(p, i->Data(), i->Len());
			if ((eType & eEncryptedFlag)) {
				if (m_fKeyIsValid) {
					// Initialize an AES structure with the Data Encrypting Key and the proper direction.
					axcl::CXecretsFileAES aesContext(axcl::CXecretsFileAESSubKey().Set(GetMasterDEK(), axcl::CXecretsFileAESSubKey::eHeaders).Get(), axcl::CXecretsFileAES::eCBC, axcl::CXecretsFileAES::eDecrypt);

					// Encrypt/Decrypt the block with default IV of zero.
					aesContext.Xblock(reinterpret_cast<const axcl::TBlock*>(p), reinterpret_cast<axcl::TBlock*>(p), static_cast<axcl::uint32>(i->Len()) / sizeof axcl::TBlock);
				}
				else {
					return NULL;
				}
			}

			return reinterpret_cast<T*>(p);
		}

	public:
		/// \brief Initialize member variables
		CXecretsFileMeta(AXCL_PARAM* pParam, int iKeyTypeDec) : std::list<CMetaSection>() {
			m_pParam = pParam;
			m_iKeyIndex = iKeyTypeDec;
			Init();
		}

		/// \brief Perform re-init to be able to hande a new file
		void Init() {
			clear();
			m_cbOffsetData = m_cbOffsetHMAC = sizeof axcl::guidAxCryptFileIdInverse;
			m_fKeyIsValid = false;
		}

		/// \brief delete owned buffers
		~CXecretsFileMeta() {
		}

		const void* Callback(int iCallbackAction, const void* p, size_t cb, int* piResult) {
			return m_pParam->pfCallback(m_pParam, iCallbackAction, p, cb, piResult);
		}

		void SetCallbackProgress(int iProgress) {
			m_pParam->iProgress = iProgress;
		}

		void SetCallbackString(int iStringIndex, const _TCHAR* sz) {
			delete[] m_pParam->strBufs[iStringIndex];
			m_pParam->strBufs[iStringIndex] = axcl::tstrdup(sz);
		}

		const _TCHAR* GetCallbackString(int iStringIndex) {
			return m_pParam->strBufs[iStringIndex];
		}

		void SetCallbackFileTime(int iFileTimeIndex, const AXCL_FILETIME& ft) {
			m_pParam->ft[iFileTimeIndex] = ft;
		}

		const AXCL_FILETIME& GetCallbackFileTime(int iFileTimeIndex) {
			return m_pParam->ft[iFileTimeIndex];
		}

		const axcl::TKey* GetDecryptKey(int iKeyIndex) {
			return reinterpret_cast<axcl::TKey*>(m_pParam->keys[iKeyIndex].pKEK);
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
		/// of this class, by comparing with CXecretsFileMeta::ClassId().
		virtual void* RTClassId() {
			return ClassId();
		}

		/// \brief Emit GUID and headers
		/// \param p Pointer to a sufficiently large memory buffer or NULL
		/// \returns The number of bytes written
		size_t Emit(void* p) {
			unsigned char* pOut = (unsigned char*)p;
			size_t cb = 0;
			if (p) {
				memcpy(pOut, axcl::guidAxCryptFileIdInverse, sizeof axcl::guidAxCryptFileIdInverse);
				if (true) for (size_t i = 0; i < sizeof axcl::guidAxCryptFileIdInverse; i++) {
					*pOut++ ^= 0xff;
				}
			}
			cb += sizeof axcl::guidAxCryptFileIdInverse;
			iterator i;
			for (i = begin(); i != end(); i++) {
				SHeader header;

				// If we have an output buffer, generate a header and then
				// write out it and the data following.
				if (p) {
					header.oType = static_cast<axcl::byte>(i->Type());
					*(AxPipe::int32*)& header.aoLength = static_cast<AxPipe::int32>(i->Len() + sizeof header);
					memcpy(pOut, &header, sizeof header);
					pOut += sizeof header;

					memcpy(pOut, i->Data(), i->Len());
					pOut += i->Len();
				}
				// Add this to the length
				cb += sizeof header + i->Len();
			}

			return cb;
		}

		static size_t GetHeaderSize() {
			return sizeof SHeader;
		}

		static size_t GetHeaderDataLen(SHeader* pHeader) {
			return *(size_t*)(pHeader->aoLength) - sizeof SHeader;
		}

		const axcl::tstring& GetError() {
			return m_sError;
		}

	public:
		bool AddSection(SHeader* pHeader, const void* pData, size_t cbData) {
			return AddSection((TBlockType)pHeader->oType, pData, cbData);
		}

		bool AddSection(TBlockType eType, const void* pData, size_t cbData) {
			// Ensure proper sequencing etc
			switch (eType) {
			case ePreamble:
				// Preamble must be first, and only once.
				if (!empty()) {
					m_sError = _TT("Preamble seen out of sequence");
					return false;
				}
				m_cbOffsetHMAC += sizeof SHeader + cbData;
				break;
			case eFileInfo:
			case eFileNameInfo:
			case eUnicodeFileNameInfo:
			case eEncryptionInfo:
			case eCompressionInfo:
			case eCompressionFlag:
			case eVersion:
				// Ensure that only one of each of these are found.
				if (FindType(eType) != end()) {
					m_sError = _TT("Illegal duplicate section found");
					return false;
				}
				break;
			case eKeyWrap1:
				// We support multiple wrappings of the key, at least potentially.
				break;
			default:
				// We silently ignore unknown meta sections
				break;
			}
			unsigned char* pCopy = axcl::arrdup<unsigned char>(pData, cbData);
			push_back(CMetaSection(eType, pCopy, cbData));

			// Add this to what we don't want to decrypt
			m_cbOffsetData += sizeof SHeader + cbData;

			if (eType == eData) {
				// Check the file version (we only support this one version 3 currently)
				if (FileVersionMajor() != m_iFileVersionMajor) {
					m_sError = _TT("New file version - cannot decrypt");
				}

				// Check that we have a key
				if (FindType(eKeyWrap1) == end()) {
					m_sError = _TT("No data encrypting key found");
				}

				// We're done in any case
				return false;
			}
			// Expect more headers
			return true;
		}

		int GetCurrentMajorVersion() {
			return m_iFileVersionMajor;
		}

		bool CheckDecryptKey() {
			// Find the appropriate key-wrap in the headers
			iterator i = FindType(eKeyWrap1);
			ASSCHK(i != end(), _T("CXecretsFileMeta::CheckDecryptKey() [No eKeyWrap1 found]"));

			// Get a pointer to the wrapped key
			SKeyWrap1* pKeyWrap = (SKeyWrap1*)(i->Data());

			// Try to unwrap it, and return the result.
			m_AesWrap.Init(*(unsigned int*)&pKeyWrap->oIter, sizeof axcl::TKey);
			return m_fKeyIsValid = (m_AesWrap.UnWrap(m_pParam->keys[m_iKeyIndex].pKEK, pKeyWrap->utKeyData, pKeyWrap->oSalt) == TRUE);
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

		bool KeyIsValid() {
			return m_fKeyIsValid;
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

		/// \brief Get a class-owned pointer to the IV (do not delete...)
		/// \return A pointer to the IV.
		axcl::TBlock* GetIV() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SEncryptionInfo> pEI(GetMetaData<SEncryptionInfo>(eEncryptionInfo));
			//SEncryptionInfo *pEI = (SEncryptionInfo *)GetMetaData(eEncryptionInfo);
			if (pEI.get()) {
				memcpy(&m_IV, &pEI->utIV, sizeof m_IV);
				return &m_IV;
			}
			return NULL;
		}

		/// \brief Get the length of the data stream, compressed or not
		/// \return The length in byte as a possibly very large number of the raw data stream.
		axcl::uint64 GetStreamSize() {
			std::auto_ptr<SData> pD(GetMetaData<SData>(eData));
			if (pD.get()) {
				axcl::uint64 cb = *reinterpret_cast<axcl::uint64*>(pD->aoDataSize);
				return cb;
			}
			return 0;
		}

		/// \brief Get the length of the decrypted data stream, possibly compressed.
		/// \return The length of the decrypted data, possibly a very large number...
		axcl::uint64 GetPlainSize() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SEncryptionInfo> pEI(GetMetaData<SEncryptionInfo>(eEncryptionInfo));
			if (pEI.get()) {
				axcl::uint64 cb = *reinterpret_cast<axcl::uint64*>(pEI->aoPlainSize);
				return cb;
			}
			return 0;
		}

		/// \brief Get the time of creation of the original file.
		/// \return The creation time in Windows standard format :-(
		AXCL_FILETIME GetCreationTime() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SFileInfo> pFI(GetMetaData<SFileInfo>(eFileInfo));
			AXCL_FILETIME ft = { 0 };
			if (pFI.get()) {
				ft = ((struct SFileTimes*)pFI->aoFileTimes)->CreationTime;
			}
			return ft;
		}

		/// \brief Get the time of last access of the original file.
		/// \return The creation time in Windows standard format :-(
		AXCL_FILETIME GetLastAccessTime() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SFileInfo> pFI(GetMetaData<SFileInfo>(eFileInfo));
			AXCL_FILETIME ft = { 0 };
			if (pFI.get()) {
				ft = ((struct SFileTimes*)pFI->aoFileTimes)->LastAccessTime;
			}
			return ft;
		}

		/// \brief Get the time of last write of the original file.
		/// \return The creation time in Windows standard format :-(
		AXCL_FILETIME GetLastWriteTime() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SFileInfo> pFI(GetMetaData<SFileInfo>(eFileInfo));
			AXCL_FILETIME ft = { 0 };
			if (pFI.get()) {
				ft = ((struct SFileTimes*)pFI->aoFileTimes)->LastWriteTime;
			}
			return ft;
		}

		/// \brief Get the Master Data Encrypting Key
		///
		/// The passphrase is used to wrap the MDEK. Here
		/// we unwrap it, using the (valid) passphrase. The MDEK
		/// in turn, is used to generate independent keys used for
		/// data encryption and header encryption etc.
		axcl::TKey* GetMasterDEK() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			return reinterpret_cast<axcl::TKey*>(m_AesWrap.GetKey());
		}

		/// \brief Get the HMAC from the headers
		/// \return An allocated pointer to the HMAC. Please delete after use.
		THmac* GetHMAC() {
			return GetMetaData<THmac>(ePreamble);
		}

		/// \brief Check the headers to see if the data is compressed
		/// \return true if the data is compress and needs decompression after decryption
		bool IsCompressed() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));
			std::auto_ptr<SCompressionFlag> pCF(GetMetaData<SCompressionFlag>(eCompressionFlag));
			if (pCF.get()) {
				bool f = (*(axcl::uint32*)pCF->aoCompFlag) != 0;
				return f;
			}
			// Old style file, always compressed.
			return true;
		}

		/// \brief Get the orginal Unicode file name from the headers, if any.
		/// \return An allocated pointer to the name (or null if not found). Please delete after use.
		wchar_t* GetUnicodeFileName() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));

			return GetMetaData<wchar_t>(eUnicodeFileNameInfo);
		}

		/// \brief Get the orginal Ansi file name from the headers, if any.
		/// \return An allocated pointer to the name. Please delete after use.
		char* GetAnsiFileName() {
			ASSCHK(m_fKeyIsValid, _TT("Attempt to read header without valid key"));

			return GetMetaData<char>(eFileNameInfo);
		}

		int GetSaveRatioForCompress() {
			return m_pParam->iZipMinSaveRatio;
		}

		size_t GetChunkSize() {
			return m_pParam->cbChunkSize;
		}
	};
} // namespace axcl

#pragma pack(pop)
#endif CXECRETSFILEMETA_H