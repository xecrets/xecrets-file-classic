#ifndef CXECRETSFILEWIN_H
#define CXECRETSFILEWIN_H
/*! \file
	\brief CAxCryptWin.cpp - The Windows implementation of CAxCrypt

	@(#) $Id$

	CAxCryptWin - The windows implementation of callbacks and functions for XecretsFileLib

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

	The author may be reached at mailto:software@axantum.com and http://www.axantum.com

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-08-06              Initial
\endverbatim
*/
#include <memory>
#include <string>

#include "resource.h"

#define WIN32_LEAN_AND_MEAN     // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <Commdlg.h>
// C RunTime Header Files
#include <tchar.h>
#include <shlwapi.h>
#include <shellapi.h>

#include <strsafe.h>

#include "../XecretsFileLib/CXecretsFileLib.h"
//#include "DynLoadString.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CXecretsFileLibWin.h"

extern axcl::tstring g_sAxCryptExtension;

namespace axcl {
	/// \brief A Windows-specific wrapper around the callback functionality of XecretsFileLib
	///
	/// The instance used must be kept alive during the entire operation.
	///
	/// The following callbacks are implemented as overridden virtual functions:
	///
	/// virtual const std::string Tchar2Ansi(axcl::tstring sTchar)  = 0;
	/// virtual const axcl::tstring Ansi2Tchar(std::string sAnsi) = 0;
	///
	/// The following callbacks must be overridden in derived classes:
	///
	/// virtual int Progress(int iPercent) = 0;
	/// virtual const axcl::tstring GetCipherPath() = 0;
	/// virtual const axcl::tstring GetPlainPath() = 0;
	///
	/// Derive operation-specific classes from this one, calling the functions of
	/// the underlying XecretsFileLib-functionality. These in turn, will at the appropriate
	/// times call these callbacks.
	///
	class CXecretsFileLibWin : public CXecretsFileLib {
		typedef CXecretsFileLib base;

	protected:
		HWND m_hWnd;
		CDlgProgress* m_pDlgProgress;

	public:
		CXecretsFileLibWin(HWND hWnd, CDlgProgress* pDlgProgress = NULL) : base() {
			m_hWnd = hWnd;
			m_pDlgProgress = pDlgProgress;
		}

	private:
		void HideProgress() {
			if (m_pDlgProgress) {
				m_pDlgProgress->Hide();
			}
		}

	private:
		void UnHideProgress() {
			if (m_pDlgProgress) {
				m_pDlgProgress->UnHide();
			}
		}

	private:
		/// \brief Report progress and check for cancel
		/// \param iPercent The percentage value 0-100 of current progress to be displayed
		/// \param return AXCL_E_OK or AXCL_E_CANCEL if a cancellation was requested by the user
		virtual int Progress(int iPercent) {
			ASSPTR(m_pParam);
			if (m_pDlgProgress) {
				if (m_pDlgProgress->IsCancelled()) {
					return AXCL_E_CANCEL;
				}
				m_pDlgProgress->StartTimer(1000);
				CProgressBarCtrl wndProgress = m_pDlgProgress->GetDlgItem(IDC_PROGRESS);
				wndProgress.SetPos(iPercent);
			}
			return AXCL_E_OK;
		}

	private:
		/// \brief Determine the full path to the cipher-text
		/// \return The resulting path, or an empty string
		virtual const axcl::tstring GetCipherPath() = 0;

	private:
		/// \brief Determine the full path to the plain-text
		/// \return The resulting path, or an empty string
		virtual const axcl::tstring GetPlainPath() = 0;

	protected:
		/// \brief Append a path plus a file name
		const axcl::tstring FolderPlusFileName(const axcl::tstring sPath, const axcl::tstring sFileName) {
			_TCHAR szTemp[_MAX_PATH];
			ASSCHK(SUCCEEDED(StringCbCopy(szTemp, sizeof szTemp, sPath.c_str())), _T("StringCbCopy() failed"));
			ASSCHK(::PathAppend(szTemp, sFileName.c_str()) == TRUE, _T("PathAppend() failed"));
			return axcl::tstring(szTemp);
		}

	protected:
		const axcl::tstring GetOutputFullPath() {
			// Build the default name from the selected output folder and the clear-text name
			// Use the Windows API to do the path-appending, unfortunately the API mixes not so well with
			// std::string/std::wstring et. al. so we just work in a temp buffer.
			_TCHAR szTmpPath[_MAX_PATH];
			ASSCHK(SUCCEEDED(StringCbCopy(szTmpPath, sizeof szTmpPath, m_sOutputFolder.c_str())), _T("StringCbCat() failed"));
			ASSPTR(m_pParam->strBufs[AXCL_STR_FILENAME]);
			PathAppend(szTmpPath, m_pParam->strBufs[AXCL_STR_FILENAME]);
			return axcl::tstring(szTmpPath);
		}

	protected:
		/// \brief transform the plain text filename into the form used for encrypted file names
		/// If there's an extension, we change that to a dash.
		/// The new extension is defined by the class
		const axcl::tstring MakeEncryptedFilePath(axcl::tstring sPlainPath) {
			const _TCHAR* szPlainPath = sPlainPath.c_str();

			// Find the extension dot, if there is one change it into a dash
			_TCHAR* szExtension = PathFindExtension(szPlainPath);
			if (*szExtension) {
				sPlainPath[szExtension - szPlainPath] = _T('-');
			}
			return sPlainPath + g_sAxCryptExtension;
		}

	protected:
		bool IsOutputFolderValid() {
			return PathIsDirectory(m_sOutputFolder.c_str()) == TRUE;
		}

	protected:
		/// \brief Build a fully qualified output path, possibly using user interaction in a SaveAs dialog
		/// \param sOutputFullPath The full path we want to write to
		/// \param bAlwaysPrompt True if we always prompt - even if the file does not exist
		/// \return The resulting path, or empty if cancel
		const axcl::tstring SaveAsPrompt(axcl::tstring sOutputFullPath, bool bAlwaysPrompt = false) {
			// Test for existance, and if so and not always prompting, just return the name.
			if (GetFileAttributes(sOutputFullPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				if (GetLastError() == ERROR_FILE_NOT_FOUND) {
					if (!bAlwaysPrompt) {
						return sOutputFullPath;
					}
				}
			}
			// Build the filter string, i.e. for example "*.txt\0*.txt\0\0"
			// They don't make it easy by using nul chars...

			_TCHAR szOutputFullPath[_MAX_PATH];
			ASSCHK(SUCCEEDED(StringCbCopy(szOutputFullPath, sizeof szOutputFullPath, sOutputFullPath.c_str())), _TT("StringCbCopy() Buffer overrun"));

			const _TCHAR* szPathExt = PathFindExtension(szOutputFullPath);
			_TCHAR szFilter[1024];
			if (szPathExt[0]) {
				ASSCHK(SUCCEEDED(StringCbPrintf(szFilter, sizeof szFilter, _T("*%s"), szPathExt)), _T("StringCbPrintf() failed"));
				_TCHAR* szFilterPart2 = &szFilter[_tcslen(szFilter) + 1];
				// The buffer size is adjusted for what's in there plus an additional reservation for the extra nul-byte
				ASSCHK(SUCCEEDED(StringCbPrintf(szFilterPart2, sizeof szFilter - (szFilterPart2 - szFilter) * sizeof _TCHAR - 1, _T("*%s"), szPathExt)), _T("StringCbPrintf failed"));
				// The double terminating nul
				szFilterPart2[_tcslen(szFilterPart2) + 1] = _T('\0');
			}
			else {
				// Copy default filter, if no extension.
				CopyMemory(szFilter, _T("*.*\0*.*\0"), sizeof _T("*.*\0*.*\0"));
			}

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = m_hWnd;
			ofn.lpstrFilter = szFilter;
			ofn.nFilterIndex = 1;
			ofn.lpstrDefExt = szPathExt[0] ? szPathExt + 1 : NULL;
			ofn.lpstrFile = szOutputFullPath;
			ofn.nMaxFile = sizeof szOutputFullPath;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

			HideProgress();
			bool bResult = GetSaveFileName(&ofn) != 0;
			UnHideProgress();

			if (!bResult) {
				return axcl::tstring();
			}

			return axcl::tstring(szOutputFullPath);
		}

	private:
		/// \brief Convert a TCHAR string into an Ansi version. Possibly this is a null-op.
		/// \param sTchar The TCHAR string to convert. If TCHAR == char, no actual conversion takes place.
		/// \return An Ansi string equivalent to the input TCHAR string
		virtual const std::string Tchar2Ansi(axcl::tstring sTchar) {
#ifdef _UNICODE
			ASSCHK(sizeof(_TCHAR) > 1, _TT("Internal configuration error - _TCHAR should be wide but appears not to be"));
			int ccNeed = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, sTchar.c_str(), -1, NULL, 0, "_", NULL);
			std::auto_ptr<char> pAnsi = std::auto_ptr<char>(new char[ccNeed]);
			ASSCHK(ccNeed == WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, sTchar.c_str(), -1, pAnsi.get(), ccNeed, "_", NULL), _TT("Internal error - Buffer overflow in call to WideCharToMultiByte()"));
			return std::string(pAnsi.get());
#else
			ASSCHK(sizeof(_TCHAR) == 1, _TT("Internal configuration error - _TCHAR should be equivalent to char but appears not to be"));
			return sTchar;
#endif
		}

	private:
		/// \brief Convert an Ansi string into a TCHAR string equivalent. Possibly a null-op.
		/// \param sAnsi The Ansi string to convert. If TCHAR == char, no actual conversion takes place.
		/// \return A TCHAR string equivalent to the input Ansi string
		virtual const axcl::tstring Ansi2Tchar(std::string sAnsi) {
#ifdef _UNICODE
			ASSCHK(sizeof(_TCHAR) > 1, _TT("Internal configuration error - _TCHAR should be wide but appears not to be"));
			int ccNeed = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, sAnsi.c_str(), -1, NULL, 0);
			std::auto_ptr<_TCHAR> pTchar = std::auto_ptr<_TCHAR>(new _TCHAR[ccNeed]);
			ASSCHK(ccNeed == MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, sAnsi.c_str(), -1, pTchar.get(), ccNeed), _TT("MultiByteToWideChar buffer overfloew"));
			return axcl::tstring(pTchar.get());
#else
			ASSCHK(sizeof(_TCHAR) == 1, _TT("Internal configuration error - _TCHAR should be equivalent to char but appears not to be"));
			return sAnsi;
#endif
		}

	private:
		/// \brief Convert a TCHAR string into an Unicode version. Possibly this is a null-op.
		/// \param sTchar The TCHAR string to convert. If TCHAR == wchar_t, no actual conversion takes place.
		/// \return An Unicode string equivalent to the input TCHAR string
		virtual const std::wstring Tchar2Unicode(axcl::tstring sTchar) {
#ifdef _UNICODE
			ASSCHK(sizeof(_TCHAR) > 1, _TT("Internal configuration error - _TCHAR should be wide but appears not to be"));
			return sTchar;
#else
			int ccNeed = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, sTchar.c_str(), -1, NULL, 0);
			std::auto_ptr<_TCHAR> pUnicode = std::auto_ptr<_TCHAR>(new _TCHAR[ccNeed]);
			ASSCHK(ccNeed == MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, sTchar.c_str(), -1, pUnicode.get(), ccNeed), _TT("MultiByteToWideChar buffer overflow"));
			return std::wstring(pUnicode.get());
#endif
		}

	private:
		/// \brief Convert an Unicode string into a TCHAR string equivalent. Possibly a null-op.
		/// \param sUnicode The Unicode string to convert. If TCHAR == wchar_t, no actual conversion takes place.
		/// \return A TCHAR string equivalent to the input Unicode string
		virtual const axcl::tstring Unicode2Tchar(std::wstring sUnicode) {
#ifdef _UNICODE
			ASSCHK(sizeof(_TCHAR) > 1, _TT("Internal configuration error - _TCHAR should be wide but appears not to be"));
			return sUnicode;
#else
			ASSCHK(sizeof(_TCHAR) == 1, _TT("Internal configuration error - _TCHAR should be equivalent to char but appears not to be"));

			int ccNeed = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, sUnicode.c_str(), -1, NULL, 0, "_", NULL);
			std::auto_ptr<char> pAnsi = std::auto_ptr<char>(new char[ccNeed]);
			ASSCHK(ccNeed == WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, sTchar.c_str(), -1, pAnsi.get(), ccNeed, "_", NULL), _TT("Internal error - Buffer overflow in call to WideCharToMultiByte()"));
			return std::string(pAnsi.get());
#endif
		}
	};
}
#endif CXECRETSFILEWIN_H