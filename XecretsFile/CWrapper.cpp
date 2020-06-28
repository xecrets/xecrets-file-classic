/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001 Svante Seleborg/Axon Data, All rights reserved.

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
	CWrapper.cpp					Batch the component operations of wrapping/unwrapping in one little class.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
									2002-08-02              Ver 1.2

*/
#include	"StdAfx.h"
#include	"CWrapper.h"
#include	"CXform.h"
#include	"CFileTemp.h"
#include    "../XecretsFileCommon/CRegistry.h"
//
//	The complete wrapping operation follows
//
CWrapper::CWrapper(CHeaders* pHeaders, HWND hProgressWnd) {
	m_pHeaders = pHeaders;
	m_hProgressWnd = hProgressWnd;
	m_fEnableProgress = true;
}
//
//	Do all operations in a wrap in one call. The headers are assumed to be open
//	and a valid data encryption key set.
//
void
CWrapper::Wrap(CFileIO& rFilePlain, CFileIO& rFileCipher, DWORD nWipePasses, BOOL fSlowSafe /* = TRUE */, BOOL fEnableProgress /*= TRUE*/) {
	m_fEnableProgress = fEnableProgress == TRUE;

	HEAP_CHECK_BEGIN(_T("Wrap() [a]"), 0)

		// Test for likely compression ratio, to decide if to compress
		CCompressRatio utRatio(NULL);
	CFileDummy utFileDummy;
	utRatio.XformData(rFilePlain, utFileDummy);
	CMessage().AppMsg(INF_COMPRESS_RATIO, rFilePlain.GetFileName(), utRatio.GetRatio()).LogEvent(2);

	BOOL fCompFlag = utRatio.GetRatio() >= (int)CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValCompressLevel).GetDword(COMPRESS_THRESHOLD);

	// 'leak' is allowed as this may cause header allocation
	// It's important that the operations are done in the same order, regardless of whether
	// compression is done or not, so the state cannot be inferred from for example the
	// order of the headers...
	//
	HEAP_CHECK_BEGIN(_T("Wrap() [b]"), TRUE);
	m_pHeaders->SetNormalSize(fCompFlag ? rFilePlain.m_qwFileSize : 0);
	m_pHeaders->SetCompressionFlag(fCompFlag);
	HEAP_CHECK_END

		rFilePlain.SetFilePointer(0);
	if (fCompFlag) {
		CFileIO utTmpFile;

		// We allow a "leak" here as MakeTmp will allocate memory for the temp file name
		HEAP_CHECK_BEGIN(_T("Wrap() [c]"), TRUE)
			// Create and make the temp file.
			utTmpFile.MakeTmp(CFileTemp().New().Get(), fSlowSafe);
		HEAP_CHECK_END

			CompressData(rFilePlain, utTmpFile);
		utTmpFile.SetFilePointer(0);
		EncryptData(utTmpFile, rFileCipher);

		if (fSlowSafe) {
			utTmpFile.WipeTemp(m_fEnableProgress ? m_hProgressWnd : NULL, nWipePasses);
		}
		utTmpFile.Close();
	}
	else {
		EncryptData(rFilePlain, rFileCipher);
	}
	HEAP_CHECK_END
}
//
//	Compress from the input to the tmp-file, in sections if necessary.
//
//
//	throws iErrorCode == IDS_error_message on error
//
void
CWrapper::CompressData(CFileIO& rFilePlain, CFileIO& rFileTmp) {
	HEAP_CHECK_BEGIN(_T("CompressData()"), FALSE);
	CCompress(m_fEnableProgress ? m_hProgressWnd : NULL).XformData(rFilePlain, rFileTmp);
	HEAP_CHECK_END
}

//
// Encrypt the compressed data
//
void
CWrapper::EncryptData(CFileIO& rFilePlain, CFileIO& rFileCipher) {
	HEAP_CHECK_BEGIN(_T("EncryptData() [a]"), 0);

	// 'leak' is allowed as this may cause header allocation, and
	// must thus be done before calculation of header size!
	HEAP_CHECK_BEGIN(_T("EncryptData() [b]"), TRUE)
		m_pHeaders->SetPlainSize(rFilePlain.m_qwFileSize);
	HEAP_CHECK_END

		// If we're appending, keep track of the original offset
		LONGLONG llBaseOffset = rFileCipher.GetFileSize();
	// Reserve space for the headers.
	rFileCipher.SetFilePointer(llBaseOffset + m_pHeaders->SizeInMemory());

	// Always use a new IV for every encryption.
	m_pHeaders->SetIV();

	// Initilialize the Xform-object with the actual Data Encrypting Key and IV, and do the transform
	CEncrypt utEncrypt(CSubKey().Set(m_pHeaders->GetDataEncKey(), CSubKey::eData).Get(), m_pHeaders->GetIV(), m_fEnableProgress ? m_hProgressWnd : NULL);

	// Set file size including expected padding.
	rFileCipher.m_qwFileSize = rFileCipher.GetFilePointer() + rFilePlain.m_qwFileSize + utEncrypt.GetPadSize(rFilePlain.m_qwFileSize);

	// Save the length of the plain text to be encrypted.
	//m_pHeaders->SetPlainSize(rFilePlain.m_qwFileSize);

	// Actually encrypt the data
	utEncrypt.XformData(rFilePlain, rFileCipher);

	// Update the length of the data block. ***This should really be done by caller! 2B-fixed***
	m_pHeaders->SetDataSize(rFileCipher.m_qwFileSize - (llBaseOffset + m_pHeaders->SizeInMemory()));
	m_pHeaders->Close();
	m_pHeaders->Save(rFileCipher, m_fEnableProgress ? m_hProgressWnd : NULL, llBaseOffset);

	// Restore file-offset to make a 'clean' exit
	rFileCipher.SetFilePointer(rFileCipher.GetFileSize());
	HEAP_CHECK_END
}
//
//	The component operations of an unwrap... Headers must be open.
//
void
CWrapper::Unwrap(CFileIO& rFileCipher, CFileIO& rFilePlain, DWORD nWipePasses, BOOL fSlowSafe /* = TRUE */, BOOL fEnableProgress/* = TRUE*/) {
	m_fEnableProgress = fEnableProgress == TRUE;

	HEAP_CHECK_BEGIN(_T("Unwrap() [a]"), 0);

	bool fTryBrokenFile = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValTryBrokenFile).GetDword(FALSE) == TRUE;

	if (m_pHeaders->IsCompressed()) {
		CFileIO utTmpFile;
		HEAP_CHECK_BEGIN(_T("Unwrap() [b]"), TRUE);

		// Create the Tmp-file
		if (fTryBrokenFile) {
			utTmpFile.Create(CFileTemp().New().Get(), fSlowSafe, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS);
		}
		else {
			utTmpFile.MakeTmp(CFileTemp().New().Get(), fSlowSafe);
		}
		HEAP_CHECK_END

			DecryptData(rFileCipher, utTmpFile);
		utTmpFile.SetFilePointer(0);
		DeCompressData(utTmpFile, rFilePlain);
		if (fSlowSafe && !fTryBrokenFile) {
			utTmpFile.WipeTemp(m_fEnableProgress ? m_hProgressWnd : NULL, nWipePasses);
		}
		utTmpFile.Close(fTryBrokenFile ? TRUE : FALSE);
	}
	else {
		DecryptData(rFileCipher, rFilePlain);
	}
	HEAP_CHECK_END
}
//
//	Take the key and an ciphertext file, produce a compressed tmp-file.
//
void
CWrapper::DecryptData(CFileIO& rFileCipher, CFileIO& rFilePlain) {
	HEAP_CHECK_BEGIN(_T("DecryptData()"), 0);
	// Check the HMAC
	// Initialize the HMAC-object
	HEAP_CHECK_BEGIN(_T("DecryptData(a)"), 0);
	CHmac utFileHMAC(m_pHeaders->GetDataEncKey(), m_fEnableProgress ? m_hProgressWnd : NULL);

	HEAP_CHECK_BEGIN(_T("DecryptData(a.a)"), 0); // ok!
	// Skip the parts of the file that should not be included in the HMAC
	rFileCipher.SetFilePointer(m_pHeaders->OffsetToHMAC());

	// Do the job
	utFileHMAC.XformData(rFileCipher, CFileDummy());

	do { // once, cheap 'try'.
		// Check the result with the stored value in the headers.
		if (memcmp(m_pHeaders->GetHMAC(), utFileHMAC.GetHMAC(), sizeof * m_pHeaders->GetHMAC()) != 0) {
			// If we have the 'try with broken HMAC set', we let the user have the option to continue.
			if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValTryBrokenFile).GetDword(FALSE)) {
				if (CMessage().AppMsg(MSG_INVALID_HMAC).ShowDialog(MB_OKCANCEL | MB_ICONERROR) == IDOK) {
					break;  // If the users says 'OK' anyway, let's try decryption anyway.
				}
			}
			CAssert(FALSE).App(MSG_INVALID_HMAC).Throw();
		}
	} while (false);

	HEAP_CHECK_END
		HEAP_CHECK_END

		// Get the size of the compressed data, exlusive of padding.
		rFilePlain.m_qwFileSize = m_pHeaders->GetPlainSize();

	// Ensure decryption starts at the right point.
	rFileCipher.SetFilePointer(m_pHeaders->SizeOnFile());

	HEAP_CHECK_BEGIN(_T("DecryptData(c)"), 0);

	// Catch errors if we're tolerant with TryBrokenFile for data recovery
	try {
		// Initilialize the Xform-object with the actual Data Encrypting Key, and run the decryption.
		CDecrypt(CSubKey().Set(m_pHeaders->GetDataEncKey(), CSubKey::eData).Get(), m_pHeaders->GetIV(), m_fEnableProgress ? m_hProgressWnd : NULL).XformData(rFileCipher, rFilePlain);
	}
	catch (TAssert utErr) {
		ConditionalThrow(utErr, utErr.LastError());
	}

	HEAP_CHECK_END

		// Reset file-offset
		rFileCipher.SetFilePointer(0);
	HEAP_CHECK_END
}
//
//	Take an input filname and produce a decompressed result in the
//	plaintext file
//
void
CWrapper::DeCompressData(CFileIO& rFileTmp, CFileIO& rFilePlain) {
	HEAP_CHECK_BEGIN(_T("DeCompressData()"), 0);

	rFilePlain.m_qwFileSize = m_pHeaders->GetNormalSize();

	// Catch errors if we're tolerant with TryBrokenFile for data recovery
	try {
		CDecompress(m_fEnableProgress ? m_hProgressWnd : NULL).XformData(rFileTmp, rFilePlain);
	}
	catch (TAssert utErr) {
		ConditionalThrow(utErr, utErr.LastError());
	}
	HEAP_CHECK_END
}