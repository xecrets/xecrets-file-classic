/*! \file
	\brief DecryptFile.cpp - Decrypt file data and meta data

	@(#) $Id$

	DecryptFile.cpp - Decrypt file data and meta data

	Copyright (C) 2005 Svante Seleborg/Axantum Software AB, All rights reserved.

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
#include "CAxCryptMeta.h"
#include "../AxPipe/CPipeFindSync.h"
#include "../AxPipe/CPipeSHA1.h"
#include "../AxPipe/CPipeHMAC_SHA1.h"
#include "../AxPipe/CPipeInflate.h"

#include "Assert.h"
#define ASSERT_FILE "DecryptFile.cpp"

namespace axcl {
	class CDecryptMeta : public axcl::CAxCryptMeta, public AxPipe::CCriticalSection {
		typedef axcl::CAxCryptMeta base;

	public:
		typedef AxPipe::CCriticalSection::Lock<CDecryptMeta> LockT;

	public:
		CDecryptMeta(AXCL_PARAM* pParam, int iKeyTypeDec) : base(pParam, iKeyTypeDec) {
		}

		/// \brief Perform an re-initing necessary to restart decryption of a file.
		void Init() {
			base::Init();
		}
	};

	/// \brief Parse Ax Crypt Meta information/headers
	/// Read and parses headers into a CAxCryptMeta object. Sends nothing
	/// downstream.
	class CPipeAxCryptDecryptMeta : public AxPipe::CFilterBlock {
		typedef AxPipe::CFilterBlock base;

	protected:
		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff
		axcl::THmac m_HMAC;                     ///< HMAC-SHA1-128 of header and data excl. preamble.
		AxPipe::CAutoSeg m_apSeg;               ///< We need to buffer a bit locally too...

	protected:
		/// \brief Locally buffering In()
		/// \param cb The number of bytes requested, or zero to return what we have
		/// \return A CSeg with data.
		/// \see CFilterBlock::In()
		AxPipe::CSeg* In(size_t cb) {
			// If we have something in the buffer...
			if (m_apSeg.get()) {
				if (!cb) {
					return m_apSeg.release();    // Return what we have
				}
				// If we have enough in the local buffer
				if (cb <= m_apSeg->Len()) {
					AxPipe::CSeg* pNewSeg = m_apSeg->Clone();
					pNewSeg->Len(cb);
					m_apSeg->Drop(cb);
					return pNewSeg;
				}
				// Not enough room - we need to complement. Create a 'large-enough' buffer
				size_t cbRest = cb - m_apSeg->Len();
				AxPipe::CSeg* pNewSeg = new AxPipe::CSeg(m_apSeg->PtrRd(), m_apSeg->Len(), cbRest);
				m_apSeg.release()->Release();

				AxPipe::CSeg* pRestSeg = ReadBlock(cbRest);
				if (pRestSeg) {
					memcpy(&pNewSeg->PtrWr()[pNewSeg->Len()], pRestSeg->PtrRd(), pRestSeg->Len());
					pRestSeg->Release();
				}
				return pNewSeg;
			}
			return ReadBlock(cb);
		}
	public:
		/// \brief Initialize member variables
		/// Initialize the constant major version we support also
		CPipeAxCryptDecryptMeta() {
			m_pDecryptMeta = NULL;
		}

	public:
		/// \brief Connect with worker and GUI keeping track of meta info
		///
		/// The Worker/GUI interface is referenced via it's base-class, so
		/// as to virtualize the references, making this code also independent
		/// of details in the GUI.
		/// \param pCAxCryptLib The library class connecting it all
		/// \return A pointer to this.
		CPipeAxCryptDecryptMeta* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			m_apSeg = NULL;
			return this;
		}

	protected:
		bool GetNextMeta() {
			// An CAutoSeg is like a CSeg except that it calls Release() when it destructs,
			// thus it can be used when premature exits from the function occur for example.
			AxPipe::CAutoSeg apSeg(In(sizeof axcl::guidAxCryptFileIdInverse));

			// If the input is empty there is no more input, so we're at end of stream.
			if (!apSeg.get()) {
				// Input is empty.
				return false;
			}

			if (!apSeg->Len()) {
				SetError(axcl::ERROR_CODE_AXCRYPT, _T("Internal error, zero-length segment"));
				return false;
			}

			if (apSeg->Len() != sizeof axcl::guidAxCryptFileIdInverse) {
				SetError(axcl::ERROR_CODE_AXCRYPT, _T("Missing GUID"));
				return false;
			}

			// Since we're storing the one's complement of the GUID, we can check for
			// equality this way.
			unsigned char s = 0;
			// Make the compiler generate proper code for 'for' based definitions
			if (true) for (int i = 0; (s == 0) && (i < sizeof axcl::guidAxCryptFileIdInverse); i++) {
				s |= apSeg->PtrRd()[i] ^ ((unsigned char*)&axcl::guidAxCryptFileIdInverse)[i] ^ 0xff;
			}
			if (s) {
				SetError(axcl::ERROR_CODE_AXCRYPT, _T("Missing GUID"));
				return false;
			}

			// Go through all the headers, and store them in the CAxCryptMeta object
			AxPipe::CAutoSeg pSegHeaderData;
			do {
				apSeg = In(sizeof CAxCryptMeta::SHeader);
				if (!apSeg.get() || apSeg->Len() != sizeof CAxCryptMeta::SHeader) {
					SetError(axcl::ERROR_CODE_AXCRYPT, _T("Could not read expected header"));
					return false;
				}

				// Get the length of the header data, following the header-header
				size_t cbHeaderData = CAxCryptMeta::GetHeaderDataLen((CAxCryptMeta::SHeader*)apSeg->PtrRd());

				// Get extra data - do not ask for zero bytes from In(), it'll get all available.
				pSegHeaderData = cbHeaderData ? In(cbHeaderData) : new AxPipe::CSeg(0);
				if (pSegHeaderData->Len() != cbHeaderData) {
					SetError(axcl::ERROR_CODE_AXCRYPT, _T("Error reading header data"));
					return false;
				}
			} while (m_pDecryptMeta->AddSection((CAxCryptMeta::SHeader*)apSeg->PtrRd(), pSegHeaderData->PtrRd(), pSegHeaderData->Len()));

			if (!m_pDecryptMeta->GetError().empty()) {
				SetError(axcl::ERROR_CODE_AXCRYPT, m_pDecryptMeta->GetError().c_str());
				return false;
			}

			if (!m_pDecryptMeta->CheckDecryptKey()) {
				SetError(axcl::ERROR_CODE_WRONGKEY, _TT("Invalid key provided"));
				return false;
			}

			// Make selected info available to the callers callbacks and return via the XecretsFileLib parameter structure

			// Start by getting the Unicode or Ansi file name from the headers, convert it to TCHAR and place it in the appropriate string buffer
			int iReturn;
			const _TCHAR* szTcharFileName = NULL;

			// If we have a Unicode file name, we prefer that...
			std::auto_ptr<wchar_t> sUnicodeFileName(m_pDecryptMeta->GetUnicodeFileName());
			if (sUnicodeFileName.get() != NULL) {
				szTcharFileName = static_cast<const _TCHAR*>(m_pDecryptMeta->Callback(AXCL_A_UNICODE2TCHAR, sUnicodeFileName.get(), 0, &iReturn));
				ASSCHK(iReturn == AXCL_E_OK, _TT("Error AXCL_A_UNICODE2TCHAR"));
			}
			else {
				// ...otherwise we must have an Ansi file name
				std::auto_ptr<char> sAnsiFileName(m_pDecryptMeta->GetAnsiFileName());
				szTcharFileName = static_cast<const _TCHAR*>(m_pDecryptMeta->Callback(AXCL_A_ANSI2TCHAR, sAnsiFileName.get(), 0, &iReturn));
				ASSCHK(iReturn == AXCL_E_OK, _TT("Error AXCL_A_ANSI2TCHAR"));
			}
			m_pDecryptMeta->SetCallbackString(AXCL_STR_FILENAME, szTcharFileName);

			// Now get the file-times from the headers, and place them in the the parameter structure
			m_pDecryptMeta->SetCallbackFileTime(AXCL_FILETIME_CT, m_pDecryptMeta->GetCreationTime());
			m_pDecryptMeta->SetCallbackFileTime(AXCL_FILETIME_LAT, m_pDecryptMeta->GetLastAccessTime());
			m_pDecryptMeta->SetCallbackFileTime(AXCL_FILETIME_LWT, m_pDecryptMeta->GetLastWriteTime());

			return true;
		}

	public:
		/// \brief The main filter override
		///
		/// Process the input, which is restricted to a single file at this point
		/// and it must start with the Ax Crypt GUID, so any preceeding
		/// data must be discarded before getting here.
		void InFilter() {
			// We call Sync(), ensuring that any pending Close() operation finishes. We then
			// know that we can delete any left-over meta data structures.
			Sync();

			// Ensure that we have exclusive access during the execution of this code. The destructor will release, if not before.
			ASSPTR(m_pDecryptMeta);
			CDecryptMeta::LockT aLock(m_pDecryptMeta);
			m_pDecryptMeta->Init();

			if (GetNextMeta()) {
				// Stop reading now, we're done - we do not want to see the rest of the file.
				SetError(AxPipe::ERROR_CODE_STOP, _T(""));
			}
		}
	};

	/// \brief Parse Ax Crypt Meta information/headers
	/// Reads and buffers data, parsing headers into a CAxCryptMeta object.
	/// Sends the raw data downstream, including the headers.
	class CPipeAxCryptMeta : public CPipeAxCryptDecryptMeta {
		typedef CPipeAxCryptDecryptMeta base;

		/// \brief Push back a segment that we've already read.
		void InPush(AxPipe::CSeg* apSeg) {
			if (m_apSeg.get() && m_apSeg->Len()) {
				SetError(AxPipe::ERROR_CODE_DERIVED, _T("Internal error in InPush()"));
			}
			else {
				// The CAutoSeg takes care of deletion if non-NULL.
				m_apSeg = apSeg;
			}
		}
	public:
		/// \brief The main filter override
		///
		/// Process the input, which may consist of several appended encrypted
		/// files, but it must start with the Ax Crypt GUID, so any preceeding
		/// data must be discarded before getting here.
		void InFilter() {
			while (true) {
				// We call Sync(), ensuring that any pending Close() operation finishes. We then
				// know that we can delete any left-over meta data structures.
				Sync();

				// Ensure that we have exclusive access during the execution of this code. The destructor will release, if not before.
				ASSPTR(m_pDecryptMeta);
				CDecryptMeta::LockT aLock(m_pDecryptMeta);
				m_pDecryptMeta->Init();

				// Get next meta data section, if any, and if correct - otherwise return
				if (!base::GetNextMeta()) {
					return;
				}

				// Open the output channel, now that we've signalled the meta data. This is a AxPipe::CFilter,
				// which means we do not propagate the Open() signal, thus we do it manually - and now is the time!
				Open();
				if (GetErrorCode()) {
					// Something bad happened when passing the signal.
					return;
				}

				// We start by re-generating the data we've cached as headers, as later stages may need it.
				// An CAutoSeg is like a CSeg except that it calls Release() when it destructs,
				// thus it can be used when premature exits from the function occur for example.
				AxPipe::CAutoSeg apSeg = new AxPipe::CSeg(m_pDecryptMeta->Emit(NULL));
				m_pDecryptMeta->Emit(apSeg->PtrWr());

				// We're done with the need for exclusive access now.
				aLock.ReleaseLock();

				Pump(apSeg->AddRef());           // Since we're keeping apSeg around we need to add a reference
				if (GetErrorCode()) {
					// Something bad happened when passing the signal.
					return;
				}

				axcl::uint64 cb = m_pDecryptMeta->GetStreamSize();

				// Now just pass through the rest of the data. Requesting zero means - take what we get.
				// We only read just enough and continue reading again if we have more to read.
				while (cb && (apSeg = In(0)).get() && apSeg->Len()) {
					// If we've received more than we need
					if (cb < apSeg->Len()) {
						AxPipe::CSeg* pLastSeg = apSeg->Clone();
						pLastSeg->Len((size_t)cb);
						apSeg->Drop((size_t)cb);
						Pump(pLastSeg);
						InPush(apSeg.release()); // Save this for later use.
						cb = 0;
					}
					else {
						apSeg->AddRef();         // AddRef since it'll CAutoSeg-destruct too.
						cb -= apSeg->Len();
						Pump(apSeg.get());
					}
				}
				// Verify that we got all we needed.
				if (cb) {
					SetError(axcl::ERROR_CODE_AXCRYPT, _T("File truncated or format error"));
				}
				Close();                        // Close the output - we're at end of this stream.
			}
		}
	};

	/// \brief Ax Crypt-specific derivation of HMAC_SHA1 calculation
	///
	/// \see AxPipe::Stock::CPipeHMAC_SHA1
	class CPipeHMAC_SHA1_128 : public AxPipe::Stock::CPipeHMAC_SHA1<128> {
	public:
		typedef AxPipe::Stock::CPipeHMAC_SHA1<128> base;

	private:
		std::auto_ptr<THmac> m_pHMAC;           ///< The HMAC from the meta data
		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff

	public:
		/// \brief Initialize member variables
		CPipeHMAC_SHA1_128() {
			m_pDecryptMeta = NULL;
		}

		CPipeHMAC_SHA1_128* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			return this;
		}

		/// \brief Setup for HMAC calculation before start of data
		///
		/// The base class will calculate the HMAC of a data stream, given
		/// a key and an offset whence to start from via a call to Init().
		/// What we do here is to call Init() with those parameters, gleaned from
		/// the meta data CAxCryptMeta pointer we got via OutSpecial.
		/// \return true to indicate the Close() should be cascaded downstream
		bool OutOpen() {
			ASSPTR(m_pDecryptMeta);                    // Just ensure that it's non-NULL

			// Get exclusive access for the duration of this block, or until released
			CDecryptMeta::LockT aLock(m_pDecryptMeta);

			// Give the base-class the key and the offset to start from.
			base::Init(reinterpret_cast<AxPipe::Stock::TBits<128>*>(axcl::CAxCryptAESSubKey().Set(m_pDecryptMeta->GetMasterDEK(),
				axcl::CAxCryptAESSubKey::eHMAC).Get()),
				m_pDecryptMeta->GetOffsetHMAC());

			// Set up the HMAC for processing.
			base::OutOpen();

			// Get and save the HMAC and the size of it.
			m_pHMAC.reset(m_pDecryptMeta->GetHMAC());
			return true;
		}

		/// \brief Override OutClose() to check for HMAC-correctness
		/// \return true to cascade the Close() call downstream
		bool OutClose() {
			ASSPTR(m_pHMAC.get());              // Just ensure that it's non-NULL

			// Finalize HMAC processing
			base::OutClose();

			// Check the HMAC that it is the same as is stored in the file, as long as we have
			// no other errors reported.
			if (!GetErrorCode()) {
				if (memcmp(m_pHMAC.get(), GetHash(), sizeof * m_pHMAC.get())) {
					SetError(axcl::ERROR_CODE_HMAC, _T("HMAC Error. File damaged."));
				}
			}
			return true;
		}
	};

	/// \brief Skip the headers from an Ax Crypt stream
	///
	/// Using info from the meta data about the offset to
	/// the data, skip bytes before starting to pass it
	/// along.
	class CPipeStripHeaders : public AxPipe::CPipe {
	public:
		typedef AxPipe::CPipe base;

	private:
		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff
		size_t m_cbSkip;                        ///< The number of bytes left to skip

	public:
		/// \brief Initialize member variables.
		CPipeStripHeaders() {
			m_cbSkip = 0;
			m_pDecryptMeta = NULL;
		}

		CPipeStripHeaders* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			return this;
		}

		bool OutOpen() {
			ASSPTR(m_pDecryptMeta);
			{
				CDecryptMeta::LockT aLock(m_pDecryptMeta);
				m_cbSkip = m_pDecryptMeta->GetOffsetData();
			}
			return base::OutOpen();
		}

		/// \brief Pass data along, after skipping the given amount of bytes
		/// \param pSeg a segment with data
		void Out(AxPipe::CSeg* pSeg) {
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
	class CPipeDecrypt : public AxPipe::CPipeBlock {
		typedef AxPipe::CPipeBlock base;

		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff
		axcl::CAxCryptAES m_AesCtx;             ///< Our decryption CBC context
		axcl::int64 m_cb;                       ///< The number of bytes to decrypt

	public:
		/// \brief Initialize member variables and the base class
		CPipeDecrypt() {
			CPipeBlock::Init(sizeof axcl::TBlock);
			m_pDecryptMeta = NULL;
		}

		CPipeDecrypt* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			return this;
		}

		bool OutOpen() {
			ASSPTR(m_pDecryptMeta);
			CDecryptMeta::LockT aLock(m_pDecryptMeta);

			// Assert that we do have a valid key
			if (!m_pDecryptMeta->KeyIsValid()) {
				SetError(axcl::ERROR_CODE_AXCRYPT, _TT("Invalid decryption key"));
				return false;
			}

			// Initialize an AES structure with the Data Encrypting Key and the proper direction.
			m_AesCtx.Init(axcl::CAxCryptAESSubKey().Set(m_pDecryptMeta->GetMasterDEK(), axcl::CAxCryptAESSubKey::eData).Get(), axcl::CAxCryptAES::eCBC, axcl::CAxCryptAES::eDecrypt);
			const axcl::TBlock* pIV = m_pDecryptMeta->GetIV();
			ASSPTR(pIV);
			m_AesCtx.SetIV(pIV);

			m_cb = m_pDecryptMeta->GetPlainSize();
			aLock.ReleaseLock();
			return base::OutOpen();
		}

		/// \brief Called at the end of one file's data stream
		///
		/// This is where we detect if there is some internal inconsistency
		/// between expected byte count and actual.
		/// \return true to pass the Close() call down the line.
		bool OutClose() {
			if (PartialBlock()) {
				SetError(AxPipe::ERROR_CODE_DERIVED, _T("Partial block detected in decrypt"));
			}
			return true;
		}

		/// \brief Decrypt a block and pass it along
		///
		/// Padding is removed, only actual plain text is passed along.
		/// \param pSeg The data to consume. Note that we're guaranteed a multiple of the block size here.
		void Out(AxPipe::CSeg* pSeg) {
			// Ensure we have a writeable destination
			AxPipe::CSeg* pOutSeg = GetSeg(pSeg->Len());
			ASSPTR(pOutSeg);

			// Here we're guaranteed an even multiple of the block size requested.
			m_AesCtx.Xblock((axcl::TBlock*)pSeg->PtrRd(), (axcl::TBlock*)pOutSeg->PtrWr(), (axcl::uint32)pOutSeg->Len() / sizeof axcl::TBlock);

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

	/// \brief Inflate (decompress) with ZLib for Ax Crypt
	///
	/// Only inflate if the stream was compressed - otherwise
	/// just pass through. Get the compress flag through the
	/// meta information
	class CPipeDecompress : public AxPipe::Stock::CPipeInflate {
		bool m_fDecompress;                     ///< true if we're to inflate
		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff
	public:
		typedef AxPipe::Stock::CPipeInflate base;

		/// \brief Intitialize member variables
		CPipeDecompress() {
			m_fDecompress = false;
			m_pDecryptMeta = NULL;
		}

		CPipeDecompress* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			return this;
		}

		/// \brief Handle open with or without compression
		/// \return the appropriate base class function return value
		bool OutOpen() {
			ASSPTR(m_pDecryptMeta);
			CDecryptMeta::LockT aLock(m_pDecryptMeta);

			// Assert that we have a valid key
			if (!m_pDecryptMeta->KeyIsValid()) {
				SetError(axcl::ERROR_CODE_WRONGKEY, _TT("Invalid decryption key"));
				return false;
			}

			// If there's a section with compression info - we're compressed.
			if ((m_fDecompress = m_pDecryptMeta->IsCompressed()) != 0) {
				return base::OutOpen();
			}
			else {
				return base::base::OutOpen();
			}
		}

		/// \brief Process one segment, possibly inflating it
		///
		/// Depending on the state of the compress/decompress flag,
		/// do inflate or pass it along unmodified.
		/// \param pSeg A segment of data
		void Out(AxPipe::CSeg* pSeg) {
			if (m_fDecompress) {
				base::Out(pSeg);
			}
			else {
				Pump(pSeg);
			}
		}

		/// \brief Handle close with or without compression
		/// \return the appropriate base class function return value
		bool OutClose() {
			if (m_fDecompress) {
				return base::OutClose();
			}
			else {
				return base::base::OutClose();
			}
		}
	};

	/// \brief Ax Crypt specific derivation which calls back for the name of the file
	///
	/// The output file name is recived via a callback.
	class CDecryptSinkFile : public AxPipe::CSinkFileIO {
	public:
		typedef AxPipe::CSinkFileIO base;

	private:
		axcl::tstring m_sFilePath;              ///< The full path to the file
		CDecryptMeta* m_pDecryptMeta;           ///< All the collective controlling stuff

	public:
		/// \brief Initialize member variables
		CDecryptSinkFile() {
			m_pDecryptMeta = NULL;
		}

		/// \brief Get a parent window handle
		/// \param hWnd A handle the window to use as parent for launch of app
		/// \return A pointer to 'this'
		CDecryptSinkFile* Init(CDecryptMeta* pDecryptMeta) {
			m_pDecryptMeta = pDecryptMeta;
			return this;
		}

		/// \brief Open the correct file name
		///
		/// We get the file name from the callback, and then use it
		/// to pass to CSinkFileIO::Init to make it open the
		/// right file.
		/// \return true to cascade the Open() call, we let CSinkFileIO decide.
		bool OutOpen() {
			ASSPTR(m_pDecryptMeta);
			int iReturn;
			const _TCHAR* szFilePath;
			{
				// Enter a critical section for the meta info-structure. This gets released by the destructor of LockT-objects
				axcl::CDecryptMeta::LockT aLock(m_pDecryptMeta);

				// Now that we have the file name from the headers in an appropriate form, let's ask for the full output path
				szFilePath = static_cast<const _TCHAR*>(m_pDecryptMeta->Callback(AXCL_A_GET_PLAIN_PATH, NULL, 0, &iReturn));
			}

			if (iReturn == AXCL_E_CANCEL) {
				SetError(axcl::ERROR_CODE_CANCEL, _TT("User cancelled in AXCL_A_GET_PLAIN_PATH"));
				return false;
			}
			if (iReturn != AXCL_E_OK) {
				SetError(axcl::ERROR_CODE_AXCRYPT, _TT("Unexpected error in AXCL_A_GET_PLAIN_PATH"));
				return false;
			}
			m_sFilePath = szFilePath;

			base::Init(szFilePath);
			return base::OutOpen();
		}

		/// \brief Set the correct file times on the still-open file
		/// \return true to cascade the call (actually that's kind of irrelevant since we're a sink...)
		bool OutClose() {
			// Ensure that we got a file name, otherwise it's a cancel.
			if (m_sFilePath.empty()) {
				SetError(axcl::ERROR_CODE_CANCEL, _T(""));
				return false;
			}

			return base::OutClose();
		}
	};
} // namespace axcl

/// \brief Decrypt a file to plain-text, using the provided parameters
///
/// Do a full decryption of a file to a destination file. The caller is responsible for
/// fixing file attributes, file modification times etc of the result.
/// A key must be provided in the parameter block.
/// A callback will be used to determine the actual output name.
/// \param pParam Various parameters, meta data is also returned here for further use by the caller
/// \param iKeyTypeDec Reference which key to use (normally AXCL_KEY_DEC).
/// \param szCipherTextFullPath The full path to the file to decrypt
int axcl_DecryptFileData(AXCL_PARAM* pParam, int iKeyTypeDec, const _TCHAR* szCipherTextFullPath) {
	axcl::CSourceProgressCancel In;
	std::auto_ptr<axcl::CDecryptMeta> pDecryptMeta(new axcl::CDecryptMeta(pParam, iKeyTypeDec));

	// Build the process sequence
	In.Append((new AxPipe::Stock::CPipeFindSync)->Init(&axcl::guidAxCryptFileIdInverse, sizeof axcl::guidAxCryptFileIdInverse, true));
	In.Append((new axcl::CPipeAxCryptMeta)->Init(pDecryptMeta.get()));
	In.Append((new axcl::CPipeHMAC_SHA1_128)->Init(pDecryptMeta.get()));
	In.Append((new axcl::CPipeStripHeaders)->Init(pDecryptMeta.get()));
	In.Append((new axcl::CPipeDecrypt)->Init(pDecryptMeta.get()));
	In.Append((new axcl::CPipeDecompress)->Init(pDecryptMeta.get()));
	In.Append((new axcl::CDecryptSinkFile)->Init(pDecryptMeta.get()));

	In.Init(pParam, szCipherTextFullPath, pParam->cbChunkSize);

	// Run the input through the pipe...
	return In.FullProcess();
}

/// \brief Decrypt file meta-data, using the provided parameters, returning the data in the parameter block
///
/// Only decrypt meta-information in the headers such as the plain-text file name.
/// A key must be provided in the parameter block.
/// \param pParam Various parameters, meta data is also returned here for further use by the caller
/// \param iKeyTypeDec Reference which key to use (normally AXCL_KEY_DEC).
/// \param szCipherTextFullPath The full path to the file to decrypt
int axcl_DecryptFileMeta(AXCL_PARAM* pParam, int iKeyTypeDec, const _TCHAR* szCipherTextFullPath) {
	axcl::CSourceProgressCancel In;
	std::auto_ptr<axcl::CDecryptMeta> pDecryptMeta(new axcl::CDecryptMeta(pParam, iKeyTypeDec));

	// Build the process sequence
	In.Append((new AxPipe::Stock::CPipeFindSync)->Init(&axcl::guidAxCryptFileIdInverse, sizeof axcl::guidAxCryptFileIdInverse, true));
	In.Append((new axcl::CPipeAxCryptDecryptMeta)->Init(pDecryptMeta.get()));
	In.Append(new AxPipe::CSinkNull);

	In.Init(pParam, szCipherTextFullPath, pParam->cbChunkSize);

	// Run the input through the pipe...
	return In.FullProcess();
}