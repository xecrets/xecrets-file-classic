#ifndef ENCDECWIN_H
#define ENCDECWIN_H
/*! \file
	\brief EncDecWin.h - The Windows implementation of Encryption/Decryption for XecretsFile2Go

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Ax Crypt for the road.

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
	2005-08-06              Initial
\endverbatim
*/

#include "../XecretsFileWinLib/CAxCryptWinLib.h"
#include "CDialogsWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "EncDecWin.h"

extern axcl::tstring g_sAxCryptExtension;   ///< The extension, if any, to use for encrypted files

class CAxCryptDecryptWin2Go : public axcl::CXecretsFileLibWin {
	typedef CXecretsFileLibWin base;

public:
	CAxCryptDecryptWin2Go(HWND hWnd, CDlgProgress* pDlgProgress = NULL) : base(hWnd, pDlgProgress) {
	}

private:
	/// \brief Determine the full path to the cipher-text
	/// \return The resulting path, or an empty string
	virtual const axcl::tstring GetCipherPath() {
		ASSPTR(m_pParam);
		return _TT("");
	}

private:
	/// \brief Determine the full path to the plain-text
	/// \return The resulting path, or an empty string
	virtual const axcl::tstring GetPlainPath() {
		ASSPTR(m_pParam);
		return m_sPlainPath = SaveAsPrompt(GetOutputFullPath());
	}

public:
	bool Decrypt(axcl::tstring sCipherPath, axcl::tstring sOutputFolder) {
		m_sCipherPath = sCipherPath;
		m_sOutputFolder = sOutputFolder;

		CDecryptPassphrase dlgPassphrase(this);
		if (dlgPassphrase.DoModal(m_hWnd) != IDOK) {
			SetErrorCode(AXCL_E_CANCEL);
			return false;
		}

		m_pDlgProgress->SetFileName(m_sCipherPath.c_str());
		m_pDlgProgress->SetOperation(_("CAxCryptDecryptWin2Go|Decrypting"));
		if (DecryptFileData(AXCL_KEY_DEC, m_sCipherPath.c_str()) != AXCL_E_OK) {
			// If the decryption failed, clean-up the partial output
			if (GetFileAttributes(m_sPlainPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				ASSAPI(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
			}
			else {
				ASSAPI(DeleteFile(m_sPlainPath.c_str()));
			}
			return false;
		}

		// Set the original file times of the plain text, ignore values that are zero in the headers.
		// This works without time conversion etc because the values in the headers of type AXCL_FILETIME are defined
		// as bit-by-bit compatible with the Windows ::FILETIME structure. Nice here, too bad in Linux etc.
		AXCL_FILETIME ftZero = { 0 };
		HANDLE hFile = ::CreateFile(m_sPlainPath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		ASSAPI(hFile != INVALID_HANDLE_VALUE);
		::FILETIME* ftCT = NULL, * ftLAT = NULL, * ftLWT = NULL;
		if (memcmp(&m_pParam->ft[AXCL_FILETIME_CT], &ftZero, sizeof(AXCL_FILETIME)) != 0) {
			ftCT = reinterpret_cast<::FILETIME*>(&m_pParam->ft[AXCL_FILETIME_CT]);
		}
		if (memcmp(&m_pParam->ft[AXCL_FILETIME_LAT], &ftZero, sizeof(AXCL_FILETIME)) != 0) {
			ftLAT = reinterpret_cast<::FILETIME*>(&m_pParam->ft[AXCL_FILETIME_LAT]);
		}
		if (memcmp(&m_pParam->ft[AXCL_FILETIME_LWT], &ftZero, sizeof(AXCL_FILETIME)) != 0) {
			ftLWT = reinterpret_cast<::FILETIME*>(&m_pParam->ft[AXCL_FILETIME_LWT]);
		}
		ASSAPI(::SetFileTime(hFile, ftCT, ftLAT, ftLWT));
		ASSAPI(::CloseHandle(hFile));

		// Now set the (relevant) file attributes to match the original encrypted file
		DWORD dwFileAttributes = ::GetFileAttributes(sCipherPath.c_str());
		ASSAPI(dwFileAttributes != INVALID_FILE_ATTRIBUTES);
		dwFileAttributes &= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM;
		ASSAPI(::SetFileAttributes(m_sPlainPath.c_str(), dwFileAttributes));
		return true;
	}
};

class CAxCryptEncryptWin2Go : public axcl::CXecretsFileLibWin {
	typedef CXecretsFileLibWin base;

public:
	CAxCryptEncryptWin2Go(HWND hWnd, CDlgProgress* pDlgProgress = NULL) : base(hWnd, pDlgProgress) {
	}

public:
	~CAxCryptEncryptWin2Go() {
	}

private:
	/// \brief Determine the full path to the cipher-text
	/// \return The resulting path, or an empty string
	virtual const axcl::tstring GetCipherPath() {
		ASSPTR(m_pParam);
		return m_sCipherPath = SaveAsPrompt(FolderPlusFileName(m_sOutputFolder, MakeEncryptedFilePath(GetFileName(m_sPlainPath))));
	}

private:
	/// \brief Determine the full path to the plain-text
	/// \return The resulting path, or an empty string
	virtual const axcl::tstring GetPlainPath() {
		ASSPTR(m_pParam);
		return _TT("");
	}

private:
	const axcl::tstring GetFileName(axcl::tstring sPath) {
		return ::PathFindFileName(sPath.c_str());
	}

public:
	bool Encrypt(axcl::tstring sPlainPath, axcl::tstring sOutputFolder) {
		m_sPlainPath = sPlainPath;
		m_sOutputFolder = sOutputFolder;

		CEncryptPassphrase dlgEncryptPassphrase(this);
		if (dlgEncryptPassphrase.DoModal(m_hWnd) != IDOK) {
			SetErrorCode(AXCL_E_CANCEL);
			return false;
		}

		m_pDlgProgress->SetFileName(m_sPlainPath.c_str());
		m_pDlgProgress->SetOperation(_("CAxCryptEncryptWin2Go|Encrypting"));
		if (EncryptFile(AXCL_KEY_ENC, m_sPlainPath.c_str(), GetFileName(sPlainPath.c_str()).c_str()) != AXCL_E_OK) {
			// If the encryption failed, clean-up the partial output
			if (GetFileAttributes(m_sCipherPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				ASSAPI(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
			}
			else {
				ASSAPI(DeleteFile(m_sCipherPath.c_str()));
			}
			return false;
		}

		// Now set the (relevant) file attributes to match the original plain-text file
		DWORD dwFileAttributes = ::GetFileAttributes(sPlainPath.c_str());
		ASSAPI(dwFileAttributes != INVALID_FILE_ATTRIBUTES);
		dwFileAttributes &= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM;
		ASSAPI(::SetFileAttributes(m_sCipherPath.c_str(), dwFileAttributes));
		return true;
	}
};
#endif // ENCDECWIN_H