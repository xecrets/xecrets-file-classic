#ifndef CXECRETSFILELIB_H
#define CXECRETSFILELIB_H
/*! \file
	\brief CXecretsFileLib.h - C++ class-wrapper for the C-callable XecretsFileLib library

	@(#) $Id$

	CAxCrypt - C++ class-wrapper for the C-callable XecretsFileLib library

	Copyright (C) 2005-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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
extern "C" {
#include "XecretsFileLib.h"
}
#include "XecretsFileLibPP.h"

#include "Assert.h"
#define ASSERT_FILE "CXecretsFileLib.h"

namespace axcl {
	/// \brief a wrapper around the C-library and callback functionality of XecretsFileLib
	///
	/// Override the virtual functions in this base class to implement the various
	/// operations. The instance used must be kept alive during the entire operation.
	///
	/// The callbacks are:
	/// private:
	///     virtual int Progress(int iPercent) = 0;
	///     virtual const axcl::tstring GetCipherPath() = 0;
	///     virtual const axcl::tstring GetPlainPath() = 0;
	///     virtual const std::string Tchar2Ansi(axcl::tstring sTchar)  = 0;
	///     virtual const axcl::tstring Ansi2Tchar(std::string sAnsi) = 0;
	///
	class CXecretsFileLib {
	protected:
		AXCL_PARAM* m_pParam;
		axcl::tstring m_sOutputFolder;          ///< The default output folder
		axcl::tstring m_sCipherPath;            ///< The full cipher path
		axcl::tstring m_sPlainPath;             ///< The full plain text path
		std::string m_sAnsiBuf;                 ///< A specifically Ansi-buffer for conversion to-from
		axcl::tstring m_sTcharBuf;              ///< A specifically Tchar-buffer for conversion to-from
		std::wstring m_sUnicodeBuf;             ///< A specifically Unicode-buffer for conversion to-from

	public:
		CXecretsFileLib() {
			m_pParam = Open(StaticCallback, this);
			ASSPTR(m_pParam);
		}

	public:
		~CXecretsFileLib() {
			if (m_pParam != NULL) {
				Close();
			}
		}

	public:
		static const void* StaticCallback(const AXCL_PARAM* pParam, int iCallbackAction, const void* p, size_t cb, int* piResult) {
			return static_cast<CXecretsFileLib*>(pParam->pCallbackContext)->InstanceCallback(pParam, iCallbackAction, p, cb, piResult);
		}

	public:
		axcl::tstring GetError() {
			return m_pParam->strBufs[AXCL_STR_ERRORMSG];
		}

	public:
		void SetErrorCode(int iResultCode) {
			m_pParam->iResultCode = iResultCode;
		}

	public:
		int GetErrorCode() {
			return m_pParam->iResultCode;
		}

	public:
		const axcl::tstring& GetThisCipherPath() {
			return m_sCipherPath;
		}

	private:
		/// \brief Report progress and check for cancel
		/// \param iPercent The percentage value 0-100 of current progress to be displayed
		/// \param return AXCL_E_OK or AXCL_E_CANCEL if a cancellation was requested by the user
		virtual int Progress(int iPercent) = 0;

	private:
		/// \brief Determine the full path to the cipher-text
		/// \return The resulting path, or an empty string
		virtual const axcl::tstring GetCipherPath() = 0;

	private:
		/// \brief Determine the full path to the plain-text
		/// \return The resulting path, or an empty string
		virtual const axcl::tstring GetPlainPath() = 0;

	private:
		/// \brief Convert a TCHAR string into an Ansi version. Possibly this is a null-op.
		/// \param sTchar The TCHAR string to convert. If TCHAR == char, no actual conversion takes place.
		/// \return An Ansi string equivalent to the input TCHAR string
		virtual const std::string Tchar2Ansi(axcl::tstring sTchar) = 0;

	private:
		/// \brief Convert an Ansi string into a TCHAR string equivalent. Possibly a null-op.
		/// \param sAnsi The Ansi string to convert. If TCHAR == char, no actual conversion takes place.
		/// \return A TCHAR string equivalent to the input Ansi string
		virtual const axcl::tstring Ansi2Tchar(std::string sAnsi) = 0;

	private:
		/// \brief Convert a TCHAR string into an Unicode version. Possibly this is a null-op.
		/// \param sTchar The TCHAR string to convert. If TCHAR == wchar_t, no actual conversion takes place.
		/// \return An Unicode string equivalent to the input TCHAR string
		virtual const std::wstring Tchar2Unicode(axcl::tstring sTchar) = 0;

	private:
		/// \brief Convert an Unicode string into a TCHAR string equivalent. Possibly a null-op.
		/// \param sUnicode The Unicode string to convert. If TCHAR == wchar_t, no actual conversion takes place.
		/// \return A TCHAR string equivalent to the input Unicode string
		virtual const axcl::tstring Unicode2Tchar(std::wstring sUnicode) = 0;

	private:
		const void* InstanceCallback(const AXCL_PARAM* pParam, int iCallbackAction, const void* p, size_t /*cb*/, int* piResult) {
			int iResult = AXCL_E_INTERNAL;
			const void* pResult = NULL;
			switch (iCallbackAction) {
			case AXCL_A_PROGRESS:               ///< Report progress and check for cancel
				iResult = Progress(pParam->iProgress);
				break;
			case AXCL_A_GET_CIPHER_PATH:        ///< You may display a SaveAs dialog (Out)
				m_sCipherPath = GetCipherPath();
				if (m_sCipherPath.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sCipherPath.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			case AXCL_A_GET_PLAIN_PATH:         ///< You may display a SaveAs dialog (Out)
				m_sPlainPath = GetPlainPath();
				if (m_sPlainPath.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sPlainPath.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			case AXCL_A_TCHAR2ANSI:             ///< Convert from TCHAR (possibly Unicode) to Ansi - possibly a null operation
				m_sAnsiBuf = Tchar2Ansi(axcl::tstring(static_cast<const _TCHAR*>(p)));
				if (m_sAnsiBuf.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sAnsiBuf.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			case AXCL_A_ANSI2TCHAR:             ///< Convert from Ansi to TCHAR (possibly Unicode) - possibly a null operation
				m_sTcharBuf = Ansi2Tchar(std::string(static_cast<const char*>(p)));
				if (m_sTcharBuf.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sTcharBuf.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			case AXCL_A_TCHAR2UNICODE:          ///< Convert from TCHAR (possibly Unicode) to Unicode - possibly a null operation
				m_sUnicodeBuf = Tchar2Unicode(axcl::tstring(static_cast<const _TCHAR*>(p)));
				if (m_sUnicodeBuf.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sUnicodeBuf.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			case AXCL_A_UNICODE2TCHAR:          ///< Convert from Unicode to TCHAR (possibly Unicode) - possibly a null operation
				m_sTcharBuf = Unicode2Tchar(std::wstring(static_cast<const wchar_t*>(p)));
				if (m_sTcharBuf.empty()) {
					iResult = AXCL_E_CANCEL;
				}
				else {
					pResult = m_sTcharBuf.c_str();
					iResult = AXCL_E_OK;
				}
				break;
			default:
				iResult = AXCL_E_BADOP;
				break;
			}
			if (piResult) {
				*piResult = iResult;
			}
			return pResult;
		}
	public:
		/// \brief Allocate and initialize a parameter block
		inline AXCL_PARAM* Open(AXCL_CALLBACK pfCallback, void* pContext) {
			return axcl_Open(pfCallback, pContext);
		}
	public:
		/// \brief Hash a key, storing the result and fingerprint in the indicated key location in the parameter block
		inline int HashKey(int iKeyType, const unsigned char* pPassphrase, size_t cbPassphrase, const _TCHAR* szKeyFullPath) {
			return axcl_HashKey(m_pParam, iKeyType, pPassphrase, cbPassphrase, szKeyFullPath);
		}
	public:
		/// \brief Decrypt a file to plain-text, using the provided parameters
		inline int DecryptFileData(int iKeyTypeDec, const _TCHAR* szCipherTextFullPath) {
			return axcl_DecryptFileData(m_pParam, iKeyTypeDec, szCipherTextFullPath);
		}
	public:
		/// \brief Decrypt file meta-data, using the provided parameters, returning the data in the parameter block
		inline int DecryptFileMeta(int iKeyTypeDec, const _TCHAR* szCipherTextFullPath) {
			return axcl_DecryptFileMeta(m_pParam, iKeyTypeDec, szCipherTextFullPath);
		}
	public:
		/// \brief Encrypt a file, using the provided parameters
		inline int EncryptFile(int iKeyTypeEnc, const _TCHAR* szPlainTextFullPath, const _TCHAR* szPlainTextFileName) {
			return axcl_EncryptFile(m_pParam, iKeyTypeEnc, szPlainTextFullPath, szPlainTextFileName);
		}
	public:
		/// \brief Re-encrypt a file under a new key, using the provided parameters
		inline int ReencryptFile(int iKeyTypeDec, int iKeyTypeEnc, const _TCHAR* szCipherTextFullPath) {
			return axcl_ReencryptFile(m_pParam, iKeyTypeDec, iKeyTypeEnc, szCipherTextFullPath);
		}
	public:
		/// \brief Free all memory resources associated with the provided parameter block
		inline void Close() {
			return axcl_Close(m_pParam);
		}
	public:
		/// \brief Allocate and initialize a new key-cache
		inline void* CacheOpen() {
			return axcl_CacheOpen();
		}
	public:
		/// \brief Store a key and it's fingerprint in the provided cache-object
		inline int CacheStoreKey(int iKeyType, void* pCache) {
			return axcl_CacheStoreKey(m_pParam, iKeyType, pCache);
		}
	public:
		/// \brief Load a key and it's fingerprint from the provided cache-object into the provided parameter block
		inline int CacheLoadKey(int iKeyType, void* pCache, const unsigned char* pFingerprint, size_t cbFingerprint) {
			return axcl_CacheLoadKey(m_pParam, iKeyType, pCache, pFingerprint, cbFingerprint);
		}
	public:
		/// \brief Search for a key that decrypts the provided file, and load it and it's fingerprint into the provided parameter block
		inline int CacheFindKey(int iKeyType, void* pCache, const _TCHAR* szInFullPath) {
			return axcl_CacheFindKey(m_pParam, iKeyType, pCache, szInFullPath);
		}
	public:
		/// \brief Free all memory resources associated with the provided parameter block
		inline void CacheClose(void* pCache) {
			return axcl_CacheClose(pCache);
		}
	};
}
#endif CXECRETSFILELIB_H