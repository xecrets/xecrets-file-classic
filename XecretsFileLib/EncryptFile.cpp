/*! \file
	\brief DecryptFile.cpp - Decrypt file data and meta data

	@(#) $Id$

	DecryptFile.cpp - Decrypt file data and meta data

	Copyright (C) 2005-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-10-28              Initial
\endverbatim
*/
#include "stdafx.h"

#include <memory>

#include "CXecretsFileLib.h"
#include "BlockTypes.h"
#include "CXecretsFileMeta.h"
#include "../AxPipe/CPipeHMAC_SHA1.h"
#include "../AxPipe/CPipeDeflate.h"

#include "Assert.h"
#define ASSERT_FILE "EncryptFile.cpp"

// TODO: Break the connection to the named object. Perhaps use static functions with run-time initializers?
extern AxPipe::CGlobalInit AxPipeGlobalInit;

namespace axcl {
	class CEncryptMeta : public axcl::CXecretsFileMeta, public AxPipe::CCriticalSection {
		typedef axcl::CXecretsFileMeta base;
	public:
		typedef AxPipe::CCriticalSection::Lock<CEncryptMeta> LockT;

	private:
		axcl::int64 m_nKeyWrapIterations;
		size_t m_cbHeaders;

	public:
		CEncryptMeta(AXCL_PARAM* pParam, int iKeyTypeDec, axcl::int64 nKeyWrapIterations = AXCL_DEFAULT_WRAP_ITERATIONS) : base(pParam, iKeyTypeDec) {
			m_nKeyWrapIterations = nKeyWrapIterations;
			m_cbHeaders = 0;
		}

	private:
		/// \brief Round a size upwards, to make the total length a multiple of the given alignment requirement
		size_t Align(size_t cbSize, size_t cbAlign) {
			// Increase the size to an even multiple of cbAling - unless it alread is
			return cbSize + (cbAlign - cbSize % cbAlign) % cbAlign;
		}

		/// \brief Allocate a properly sized data-block, and initialize it with random data
		/// \param eType The type of block - determines the alignment rounding
		/// \param cbSize The size of data. Is updated to the actual size allocated.
		template<class T> T* Alloc(axcl::TBlockType eType, size_t& cbSize) {
			// Allocate in secure memory. Round size upwards to encryption block if encrypted, otherwise just a word
			cbSize = Align(cbSize, (eType & eEncryptedFlag) ? sizeof axcl::TBlock : sizeof axcl::int32);
			unsigned char* pBuf = new unsigned char[cbSize];
			AxPipeGlobalInit.Random(pBuf, cbSize);
			return reinterpret_cast<T*>(pBuf);
		}

		/// \brief Get an existing, or allocate a properly sized data-block and initialize it with random data
		/// \param eType The type of block - determines the alignment rounding
		/// \param cbSize The size of data. Is updated to the actual size allocated.
		template<class T> std::auto_ptr<T> GetOrAlloc(axcl::TBlockType eType, size_t& cbSize) {
			std::auto_ptr<T> p(GetMetaData<T>(eType, &cbSize));
			if (p.get() == NULL) {
				p.reset(Alloc<T>(eType, cbSize));
			}
			return p;
		}

	private:
		/// \brief Endian-independent store of ints in little-endian format.
		template<class T> void SetInt(axcl::byte aoValue[sizeof T], T v) {
			for (int i = 0; i < sizeof v; i++) {
				aoValue[i] = static_cast<axcl::byte>(v & 0xff);
				v >>= 8;
			}
		}

	private:
		/// \brief Ensure that it gets encrypted, if necessary
		void
			EncryptIfNecessary(TBlockType eType, void* p, size_t cb) {
			if ((eType & eEncryptedFlag)) {
				ASSCHK(m_fKeyIsValid, _TT("Attempt to add header without valid key"));

				// Initialize an AES structure with the Data Encrypting Key and the proper direction.
				axcl::CXecretsFileAES aesContext(axcl::CXecretsFileAESSubKey().Set(GetMasterDEK(), axcl::CXecretsFileAESSubKey::eHeaders).Get(), axcl::CXecretsFileAES::eCBC, axcl::CXecretsFileAES::eEncrypt);

				// Encrypt/Decrypt the block with default IV of zero.
				aesContext.Xblock(static_cast<axcl::TBlock*>(p), static_cast<axcl::TBlock*>(p), cb / sizeof axcl::TBlock);
			}
		}

	protected:
		/// \brief Encrypt a section (in-place!) if necessary, and the add it to the collection of headers
		/// \param eType The type of the section
		/// \param p Pointer to the data of the section
		/// \param cb The number of bytes in the data of the section
		/// \return true if more headers are expected
		bool AddSection(TBlockType eType, void* p, size_t cb) {
			EncryptIfNecessary(eType, p, cb);
			return base::AddSection(eType, p, cb);
		}

		/// \brief Add or Update a section
		bool UpdateSection(TBlockType eType, void* pData, size_t cbData) {
			iterator it;
			if ((it = FindType(eType)) == end()) {
				return AddSection(eType, pData, cbData);
			}
			ASSCHK(it->Len() == cbData, _TT("Internal error, size mismatch in UpdateSection()"));
			EncryptIfNecessary(eType, pData, cbData);
			memcpy(it->Data(), pData, cbData);
			return eType != eData;
		}

	public:
		/// \return true if all appears ok
		bool SetDecryptKey(const axcl::TKey* pDecryptKey) {
			// Allocate room for a key
			size_t cb = sizeof SKeyWrap1;
			std::auto_ptr<SKeyWrap1> pKeyWrap1(Alloc<SKeyWrap1>(eKeyWrap1, cb));

			// Wrap it - we know that Alloc has filled the data area with random data, so we have a nice key and
			// a nice salt with no further effort.
			SetInt<axcl::int32>(pKeyWrap1->oIter, static_cast<axcl::int32>(m_nKeyWrapIterations));

			// Save the un-wrapped version so we can restore the key used for encryption
			std::auto_ptr<SKeyWrap1> pKeyWrapSave(axcl::objdup<SKeyWrap1>(pKeyWrap1.get()));

			// Do the wrap, and then copy the result to our key data
			m_AesWrap.Init(m_nKeyWrapIterations, sizeof axcl::TKey);
			m_AesWrap.Wrap(pDecryptKey, pKeyWrap1->utKeyData, pKeyWrap1->oSalt);
			memcpy(pKeyWrap1->utKeyData, m_AesWrap.GetWrap(), m_AesWrap.WrapSize());

			// Now restore the unwrapped master key encrypting key, since we want to use it for encryption/decryption
			// TODO: Fix the AesWrap-class to fit the needs better
			m_AesWrap.SetKeyAndSalt(pKeyWrapSave->utKeyData, pKeyWrapSave->oSalt);

			// Store the wrapped version in the headers
			return m_fKeyIsValid = AddSection(eKeyWrap1, pKeyWrap1.get(), cb);;
		}

		/// \return true if all appears ok
		bool SetDecryptKey(int iKeyIndex) {
			return SetDecryptKey(GetDecryptKey(iKeyIndex));
		}

	public:
		/// \brief Add ePreamble section with the HMAC to the headers
		/// \param pHmac Pointer to the HMAC - or null to set it to filler for now
		/// \return true if all appears ok
		bool SetPreamble(const THmac* pHmac) {
			size_t cb = sizeof SPreamble;
			std::auto_ptr<SPreamble> pPreamble = GetOrAlloc<SPreamble>(ePreamble, cb);

			if (pHmac != NULL) {
				memcpy(&pPreamble->utHMAC, pHmac, sizeof pPreamble->utHMAC);
			}
			return UpdateSection(ePreamble, pPreamble.get(), cb);
		}

	public:
		/// \brief Add eVersion section to the headers
		/// \return true if all appears ok
		bool SetVersion(int iProgramVersionMajor, int iProgramVersionMinor, int iProgramVersionMinuscle) {
			size_t cb = sizeof SVersion;
			std::auto_ptr<SVersion> pVersion(Alloc<SVersion>(eVersion, cb));

			pVersion->oFileVersionMajor = m_iFileVersionMajor;
			pVersion->oFileVersionMinor = m_iFileVersionMinor;
			pVersion->oVersionMajor = static_cast<axcl::byte>(iProgramVersionMajor);
			pVersion->oVersionMinor = static_cast<axcl::byte>(iProgramVersionMinor);
			pVersion->oVersionMinuscle = static_cast<axcl::byte>(iProgramVersionMinuscle);

			return AddSection(eVersion, pVersion.get(), cb);
		}

	public:
		/// \brief Add eCompressionFlag section to the headers
		/// \return true if all appears ok
		bool SetCompressionFlag(bool fCompression) {
			size_t cb = sizeof SCompressionFlag;
			std::auto_ptr<SCompressionFlag> pCompressionFlag = GetOrAlloc<SCompressionFlag>(eCompressionFlag, cb);

			SetInt<axcl::int32>(pCompressionFlag->aoCompFlag, fCompression ? 1 : 0);

			return UpdateSection(eCompressionFlag, pCompressionFlag.get(), cb);
		}

	public:
		/// \brief Add eCompressionFlag section to the headers
		/// \return true if all appears ok
		bool SetCompressionInfo(axcl::int64 cbNormalSize) {
			size_t cb = sizeof SCompressionInfo;
			std::auto_ptr<SCompressionInfo> pCompressionInfo = GetOrAlloc<SCompressionInfo>(eCompressionInfo, cb);

			SetInt<axcl::int64>(pCompressionInfo->aoNormalSize, cbNormalSize);

			return UpdateSection(eCompressionInfo, pCompressionInfo.get(), cb);
		}

	public:
		/// \brief Add eFileInfo with the file times to the headers
		/// \return true if all appears ok
		bool SetFileInfo(const AXCL_FILETIME& ftCT, const AXCL_FILETIME& ftLAT, const AXCL_FILETIME& ftLWT) {
			size_t cb = sizeof SFileTimes;
			std::auto_ptr<SFileTimes> pFileTimes(Alloc<SFileTimes>(eFileInfo, cb));

			// Set the actual values
			pFileTimes->CreationTime = ftCT;
			pFileTimes->LastAccessTime = ftLAT;
			pFileTimes->LastWriteTime = ftLWT;

			return AddSection(eFileInfo, pFileTimes.get(), cb);
		}

		/// \return true if all appears ok
		bool SetFileInfo() {
			return SetFileInfo(GetCallbackFileTime(AXCL_FILETIME_CT), GetCallbackFileTime(AXCL_FILETIME_LAT), GetCallbackFileTime(AXCL_FILETIME_LWT));
		}

	public:
		/// \brief Add eFileNameInfo with the original file name to the headers
		/// \param sFileName a string with the file name
		/// \return true if all appears ok
		bool SetFileNameInfo(const _TCHAR* tzFileName) {
			int iReturn;

			// First add an Unicode version
			const wchar_t* sUnicodeFileName = static_cast<const wchar_t*>(Callback(AXCL_A_TCHAR2UNICODE, tzFileName, 0, &iReturn));
			ASSCHK(iReturn == AXCL_E_OK, _TT("AXCL_A_TCHAR2UNICODE failed"));

			size_t cbUnicodeFileName = (wcslen(sUnicodeFileName) + 1) * sizeof(wchar_t);
			size_t cb = sizeof SUnicodeFileNameInfo + cbUnicodeFileName;
			std::auto_ptr<SUnicodeFileNameInfo> pUnicodeFileNameInfo(Alloc<SUnicodeFileNameInfo>(eUnicodeFileNameInfo, cb));

			memcpy(pUnicodeFileNameInfo->wzFileName, sUnicodeFileName, cbUnicodeFileName);

			if (!AddSection(eUnicodeFileNameInfo, pUnicodeFileNameInfo.get(), cb)) {
				return false;
			}

			// Then add an Ansi version
			const char* sAnsiFileName = static_cast<const char*>(Callback(AXCL_A_TCHAR2ANSI, tzFileName, 0, &iReturn));
			ASSCHK(iReturn == AXCL_E_OK, _TT("AXCL_A_TCHAR2ANSI failed"));

			size_t cbFileName = strlen(sAnsiFileName) + 1;
			cb = sizeof SFileNameInfo + cbFileName;
			std::auto_ptr<SFileNameInfo> pFileNameInfo(Alloc<SFileNameInfo>(eFileNameInfo, cb));

			memcpy(pFileNameInfo->szFileName, sAnsiFileName, cbFileName);

			return AddSection(eFileNameInfo, pFileNameInfo.get(), cb);
		}

		/// \return true if all appears ok
		bool SetFileNameInfo() {
			return SetFileNameInfo(GetCallbackString(AXCL_STR_FILENAME));
		}

	public:
		/// \return true if all appears ok
		bool SetEncryptionInfo(axcl::int64 cbPlainSize) {
			size_t cb = sizeof SEncryptionInfo;

			// This also fills the buffer with random data
			std::auto_ptr<SEncryptionInfo> pEncryptionInfo = GetOrAlloc<SEncryptionInfo>(eEncryptionInfo, cb);

			// Set the size
			SetInt<axcl::int64>(pEncryptionInfo->aoPlainSize, cbPlainSize);
			return UpdateSection(eEncryptionInfo, pEncryptionInfo.get(), cb);
		}

	public:
		/// \brief Set the length of the possibly padded encrypted data stream
		/// \return true if all appears ok
		bool SetDataSize(axcl::int64 cbDataSize) {
			size_t cb = sizeof SData;

			std::auto_ptr<SData> pData = GetOrAlloc<SData>(eData, cb);

			// Set the size
			SetInt<axcl::int64>(pData->aoDataSize, cbDataSize);
			// This is kind of tricky... UpdateSection returns true if we are to expect more headers. We should not be expecting more at this time.
			return !UpdateSection(eData, pData.get(), cb);
		}

	public:
		void RememberHeaderLen() {
			m_cbHeaders = Emit(NULL);
		}

	public:
		bool VerifyHeaderLen() {
			return m_cbHeaders == Emit(NULL);
		}
	};

	/// \brief Build headers, excluding HMAC and other info that needs filling at the end
	class CPipePreHeaders : public AxPipe::CPipe {
		typedef AxPipe::CPipe base;
	private:
		CEncryptMeta* m_pEncryptMeta;
		axcl::int64 m_cb;

	public:
		CPipePreHeaders() {
			m_pEncryptMeta = NULL;
			m_cb = 0;
		};

	public:
		CPipePreHeaders* Init(CEncryptMeta* pEncryptMeta) {
			m_pEncryptMeta = pEncryptMeta;
			return this;
		}

	public:
		bool OutOpen() {
			ASSPTR(m_pEncryptMeta);

			{ // Critical Section
				CEncryptMeta::LockT aLockOnLib(m_pEncryptMeta);

				// Placeholder section for the HMAC - will be filled in after encryption
				if (!m_pEncryptMeta->SetPreamble(NULL)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set preamble"));
					return false;
				}

				// Set the version information. There's (yet another) mistaken idea in the file format. It contains the
				// version of the software that writes the file, but no identifier as to which software... The really
				// important piece of info is the file version, the program version is just informative, but it's not
				// really that useful without an id as well. To be fixed...
				// TODO: For now, we set the program version 0.0.0 here. Should probably reflect something else.
				if (!m_pEncryptMeta->SetVersion(0, 0, 0)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set version"));
					return false;
				}

				// Generate a master key, wrap it using the provided passphrase-derived key
				if (!m_pEncryptMeta->SetDecryptKey(AXCL_KEY_ENC)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set passphrase"));
					return false;
				}

				// Store original file times in the headers
				if (!m_pEncryptMeta->SetFileInfo()) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set file info"));
					return false;
				}

				// Store the original file name in the headers
				if (!m_pEncryptMeta->SetFileNameInfo()) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set file name info"));
					return false;
				}

				// Set the IV, and a place-holder for the length of the plain-text, which we don't know yet
				if (!m_pEncryptMeta->SetEncryptionInfo(0)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set encryption info"));
					return false;
				}

				// Compression flag place-holder
				if (!m_pEncryptMeta->SetCompressionFlag(false)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set compression flag"));
					return false;
				}

				// Compression info place-holder
				if (!m_pEncryptMeta->SetCompressionInfo(0)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set compression info"));
					return false;
				}

				// Set a placeholder for the final size of the encrypted data stream, including padding
				if (!m_pEncryptMeta->SetDataSize(0)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Failed to set encrypted data size"));
					return false;
				}

				// The length of the headers must not change from now, so remember this length
				m_pEncryptMeta->RememberHeaderLen();
			}
			return base::OutOpen();
		}

	public:
		void Out(AxPipe::CSeg* pSeg) {
			m_cb += pSeg->Len();
			Pump(pSeg);
		}
	};

	/// \brief Compress a stream, if it meets the appropriate ratio for the first chunk
	class CPipeCompressAxCrypt : public AxPipe::Stock::CPipeDeflate {
		typedef AxPipe::Stock::CPipeDeflate base;
		CEncryptMeta* m_pEncryptMeta;           ///< All the collective controlling stuff

	public:
		CPipeCompressAxCrypt() {
			m_pEncryptMeta = NULL;
		}

	public:
		CPipeCompressAxCrypt* Init(CEncryptMeta* pEncryptMeta) {
			m_pEncryptMeta = pEncryptMeta;

			base::Init(m_pEncryptMeta->GetSaveRatioForCompress(), m_pEncryptMeta->GetChunkSize(), m_pEncryptMeta->GetChunkSize());
			return this;
		}

	public:
		bool OutClose() {
			bool fReturn = base::OutClose();

			// Use a 'break'able do-while(false)-block to enable us to exit this block cleanly and continue
			do {
				CEncryptMeta::LockT aLockOnEncryptMeta(m_pEncryptMeta);

				// Remember the number of bytes of the uncompressed data too
				if (!m_pEncryptMeta->SetCompressionInfo(base::GetInputSize())) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("SetCompressionInfo() failed"));
					break;
				}

				// Update to the correct value of the byte count for the plain-text - compressed or not
				if (!m_pEncryptMeta->SetEncryptionInfo(base::GetOutputSize())) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("SetEncryptionInfo() failed"));
					break;
				}

				// Update to the actual value for compression
				if (!m_pEncryptMeta->SetCompressionFlag(IsDeflating())) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("SetCompressionFlag() failed"));
					break;
				}
			} while (false);
			return fReturn;
		}
	};

	/// \brief AxEncrypt a raw stream of bytes.
	///
	/// To simplify the logic
	/// here, we ust the filter chunk paradigm - we know that
	/// the blocks will tend to arrive in nice chunks anyway.
	/// This is the actual encryptor, it expects to only see
	/// a stream of plain-text blocks to encrypt.
	/// The key comes from m_pCXecretsFileLib->m_pCXecretsFileMeta which must be prepared for encryption
	class CPipeEncrypt : public AxPipe::CPipeBlock {
		typedef AxPipe::CPipeBlock base;

		CEncryptMeta* m_pEncryptMeta;           ///< All the collective controlling stuff
		axcl::CXecretsFileAES m_AesCtx;             ///< Our encryption CBC context
		axcl::int64 m_cb;                       ///< The number of bytes in the encrypted stream, including padding

	public:
		/// \brief Initialize member variables and the base class
		CPipeEncrypt() {
			CPipeBlock::Init(sizeof axcl::TBlock);
			m_pEncryptMeta = NULL;
		}

		CPipeEncrypt* Init(CEncryptMeta* pEncryptMeta) {
			m_pEncryptMeta = pEncryptMeta;
			return this;
		}

		bool OutOpen() {
			ASSPTR(m_pEncryptMeta);
			{
				// Enter a critical section. Destructor releases.
				CEncryptMeta::LockT aLock(m_pEncryptMeta);

				// Assert that we do have a valid key
				if (!m_pEncryptMeta->KeyIsValid()) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Invalid encryption key"));
					return false;
				}
				// Initialize an AES structure with the Data Encrypting Key and the proper direction.
				m_AesCtx.Init(axcl::CXecretsFileAESSubKey().Set(m_pEncryptMeta->GetMasterDEK(), axcl::CXecretsFileAESSubKey::eData).Get(), axcl::CXecretsFileAES::eCBC, axcl::CXecretsFileAES::eEncrypt);
				const axcl::TBlock* pIV = m_pEncryptMeta->GetIV();
				ASSPTR(pIV);
				m_AesCtx.SetIV(pIV);

				m_cb = 0;
			}
			return base::OutOpen();
		}

		/// \brief Called at the end of one file's data stream
		///
		/// This is where we output the final padding block
		/// \return true to pass the Close() call down the line.
		bool OutClose() {
			if (!GetErrorCode()) {
				// Handle padding.
				// The padding scheme is from RFC 1423 adapted to 16-byte blocks
				// If necessary, a full block of padding-only is emitted. The partial
				// block is filled with the required number of bytes, each of which has
				// as value the number of padding bytes.
				AxPipe::CSeg* pPartial = new AxPipe::CSeg(sizeof axcl::TBlock);

				size_t cbPad = pPartial->Len();     // Default is a full block of just pad...
				// ...unless we have a partial block left to encrypt
				if (PartialBlock()) {
					// The number of bytes to pad is determined by the block size minus what we have
					cbPad = pPartial->Len() - PartialBlock()->Len();
					// Copy what we have into the final block
					memcpy(pPartial->PtrWr(), PartialBlock()->PtrRd(), PartialBlock()->Len());
				}
				// Fill the non-used part of the block with the number of pad bytes
				memset(&pPartial->PtrWr()[pPartial->Len() - cbPad], static_cast<int>(cbPad), cbPad);

				// Encrypt and send it onwards, release the provided segment as well
				Out(pPartial);

				// Update to the correct value of the byte count for the data section
				if (!m_pEncryptMeta->SetDataSize(m_cb)) {
					SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("SetDataSize() failed"));
				}
			}

			// Always call the base-class, as it may need to clean up
			return base::OutClose();
		}

		/// \brief Encrypt a block and pass it along
		///
		/// Padding is added in the OutClose() method
		/// \param pSeg The data to consume. Note that we're guaranteed a multiple of the block size here.
		void Out(AxPipe::CSeg* pSeg) {
			// Ensure we have a writeable destination
			AxPipe::CSeg* pOutSeg = GetSeg(pSeg->Len());
			ASSPTR(pOutSeg);

			// Here we're guaranteed an even multiple of the block size requested.
			m_AesCtx.Xblock(reinterpret_cast<const axcl::TBlock*>(pSeg->PtrRd()),
				reinterpret_cast<axcl::TBlock*>(pOutSeg->PtrWr()),
				pOutSeg->Len() / sizeof axcl::TBlock);

			pSeg->Release();                    // Release the source

			m_cb += pOutSeg->Len();

			// Send the encrypted blocks onwards
			Pump(pOutSeg);
		}
	};

	/// \brief Xecrets File Classic encryption specific derivation of HMAC_SHA1 calculation
	///
	/// \see AxPipe::Stock::CPipeHMAC_SHA1
	class CPipeEncHMAC_SHA1_128 : public AxPipe::Stock::CPipeHMAC_SHA1<128> {
	public:
		typedef AxPipe::Stock::CPipeHMAC_SHA1<128> base;

	private:

	public:
		CPipeEncHMAC_SHA1_128* Init(CEncryptMeta* pEncryptMeta) {
			// Give the base-class the key and the offset to start from.
			base::Init(reinterpret_cast<AxPipe::Stock::TBits<128>*>(CXecretsFileAESSubKey().Set(pEncryptMeta->GetMasterDEK(), CXecretsFileAESSubKey::eHMAC).Get()),
				pEncryptMeta->GetOffsetHMAC());
			return this;
		}
	};

	/// \brief Xecrets File Classic specific derivation which calls back for the name of the file
	///
	/// The output file name is recived via a callback.
	class CEncryptSinkFile : public AxPipe::CSinkFileIO {
	public:
		typedef AxPipe::CSinkFileIO base;

	private:
		axcl::tstring m_sFilePath;              ///< The full path to the file
		CEncryptMeta* m_pEncryptMeta;           ///< All the collective controlling stuff

	public:
		/// \brief Initialize member variables
		CEncryptSinkFile() {
			m_pEncryptMeta = NULL;
		}

		/// \brief Get a parent window handle
		/// \param hWnd A handle the window to use as parent for launch of app
		/// \return A pointer to 'this'
		CEncryptSinkFile* Init(CEncryptMeta* pEncryptMeta) {
			m_pEncryptMeta = pEncryptMeta;
			return this;
		}

		/// \brief Open the correct file name
		///
		/// We get the file name from the callback, and then use it
		/// to pass to CSinkFileIO::Init to make it open the
		/// right file.
		/// \return true to cascade the Open() call, we let CSinkFileIO decide.
		bool OutOpen() {
			ASSPTR(m_pEncryptMeta);
			int iReturn;
			const _TCHAR* szFilePath;
			{
				// Enter a critical section for the meta info-structure. This gets released by the destructor of LockT-objects
				axcl::CEncryptMeta::LockT aLock(m_pEncryptMeta);

				// Now that we have the file name from the headers in an appropriate form, let's ask for the full output path
				szFilePath = static_cast<const _TCHAR*>(m_pEncryptMeta->Callback(AXCL_A_GET_CIPHER_PATH, NULL, 0, &iReturn));
			}

			if (iReturn == AXCL_E_CANCEL) {
				SetError(axcl::ERROR_CODE_CANCEL, _TT("User cancelled in AXCL_A_GET_CIPHER_PATH"));
				return false;
			}
			if (iReturn != AXCL_E_OK) {
				SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Unexpected error in AXCL_A_GET_CIPHER_PATH"));
				return false;
			}
			m_sFilePath = szFilePath;

			base::Init(szFilePath);
			bool fOpenResult = base::OutOpen();

			// Allocate a new memory segment just large enough for the place-holder headers.
			AxPipe::CSeg* pSeg = new AxPipe::CSeg(m_pEncryptMeta->Emit(NULL));
			if (m_pEncryptMeta->Emit(pSeg->PtrWr()) != pSeg->Len()) {
				SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Internal error, length inconsistency between two calls to CXecretsFileMeta::Emit()"));
				return false;
			}
			Out(pSeg);

			return fOpenResult;
		}

	private:
		/// \brief A helper to allow easy early abort if an error occurs during processing
		void OutCloseHelper() {
			// Ensure that we got a file name, otherwise it's a cancel.
			if (m_sFilePath.empty()) {
				SetError(axcl::ERROR_CODE_CANCEL, _T(""));
				return;
			}

			if (!m_pEncryptMeta->VerifyHeaderLen()) {
				SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Internal error, header length has been modified - cannot fixup headers!"));
				return;
			}

			// Start with setting the end-of-file position "here"
			base::SetFileEnd();

			// Rewind to the start
			base::SetFilePos(0);

			// Allocate a new memory segment just large enough for the freshly re-generated buffers.
			AxPipe::CSeg* pSeg = new AxPipe::CSeg(m_pEncryptMeta->Emit(NULL));
			if (m_pEncryptMeta->Emit(pSeg->PtrWr()) != pSeg->Len()) {
				SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Internal error, length inconsistency between two calls to CXecretsFileMeta::Emit()"));
				return;
			}
			Out(pSeg);

			// Synchronize
			Sync();

			// Rewind to the start, again...
			base::SetFilePos(0);

			{
				AxPipe::CSourceFileIO InHMAC;
				CPipeEncHMAC_SHA1_128* pEncHMAC = (new CPipeEncHMAC_SHA1_128)->Init(m_pEncryptMeta);
				InHMAC.Append(pEncHMAC);
				InHMAC.Append(new AxPipe::CSinkNull);

				InHMAC.Init(this);

				// Run the input through the pipe...
				if (InHMAC.Open()->Drain()->Close()->Plug()->GetErrorCode() != AxPipe::ERROR_CODE_SUCCESS) {
					SetError(InHMAC.GetErrorCode(), InHMAC.GetErrorMsg());
					return;
				}

				m_pEncryptMeta->SetPreamble(reinterpret_cast<const THmac*>(pEncHMAC->GetHash()));
			}

			// Rewind to the start, again and again...
			base::SetFilePos(0);

			// Allocate a new memory segment just large enough for the freshly re-generated buffers.
			pSeg = new AxPipe::CSeg(m_pEncryptMeta->Emit(NULL));
			if (m_pEncryptMeta->Emit(pSeg->PtrWr()) != pSeg->Len()) {
				SetError(axcl::ERROR_CODE_XECRETSFILE, _TT("Internal error, length inconsistency between two calls to CXecretsFileMeta::Emit()"));
				return;
			}
			Out(pSeg);

			// Synchronize
			Sync();

			// Finally, move the file-pointer back to the end, so base::OutClose() does not truncate the file
			base::SetFilePos(base::FileSize());
		}
	public:

		/// \brief Rewind and rewrite the updated headers.
		/// \return true to cascade the call (actually that's kind of irrelevant since we're a sink...)
		bool OutClose() {
			// Close as best can
			OutCloseHelper();

			// Always call the base class, as it may need to cleanup
			return base::OutClose();
		}
	};
}

/// \brief Encrypt a plain-text file.
/// \return The full path to the resulting encrypted file
int axcl_EncryptFile(AXCL_PARAM* pParam, int iKeyTypeEnc, const _TCHAR* szPlainTextFullPath, const _TCHAR* szPlainTextFileName) {
	axcl::CSourceProgressCancel In;
	std::auto_ptr<axcl::CEncryptMeta> pEncryptMeta(new axcl::CEncryptMeta(pParam, iKeyTypeEnc));

	// Build the process sequence
	In.Append((new axcl::CPipePreHeaders)->Init(pEncryptMeta.get()));
	In.Append((new axcl::CPipeCompressAxCrypt)->Init(pEncryptMeta.get()));
	In.Append((new axcl::CPipeEncrypt)->Init(pEncryptMeta.get()));

	// ...and finally accept the stream, and at the end rewind, fixup the headers and do a new pass and patch the HMAC...
	In.Append((new axcl::CEncryptSinkFile)->Init(pEncryptMeta.get()));

	// Pass the recommended plain-text filename in the parameter block
	delete[] pParam->strBufs[AXCL_STR_FILENAME];
	pParam->strBufs[AXCL_STR_FILENAME] = axcl::tstrdup(szPlainTextFileName);

	In.Init(pParam, szPlainTextFullPath, pParam->cbChunkSize);

	// Run the input through the pipe...
	return In.FullProcess();
}