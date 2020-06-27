#ifndef CDIALOGSWIN_H
#define CDIALOGSWIN_H
/*! \file
	\brief CDialogsWin.h - Various dialogs for XecretsFile2Go

	@(#) $Id$

*/
/*! \page License CDialogsWin.h - Various dialogs for XecretsFile2Go

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
----
*/
/*! \mainpage CDialogsWin.h - Various dialogs for XecretsFile2Go

	\author
	Svante Seleborg/Axantum Software AB

	\par License:
	\ref License "GNU General Public License"

	This is an implementation of various dialogs for XecretsFile2Go, with the following design goals

	- Use WTL/ATL for the basic implementation

	- Use gettext-style strings for translation purposes. No strings in the resources.

	- Support safe getting of passphrases, safe in the sense that they are placed in memory allocated
	  via 'new', which thus may be globally overloaded to provide safe storage, i.e. memory which is kept
	  track of and not placed in the swap file etc.

*/
#include "resource.h"

#include "CDialogs.h"
#include "../AxWinLib/CVersionWin.h"
#include "CConfigWin.h"

#include <strsafe.h>

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CDialogsWin.h"

class CFileFilter {
	axcl::tstring m_sFilter;
	axcl::tstring m_sDefaultName;
	axcl::tstring m_sDefaultExtension;

public:
	void SetDefault(const axcl::tstring& sDefaultName) {
		m_sDefaultName = sDefaultName;
		m_sDefaultExtension = PathFindExtension(sDefaultName.c_str());
	}

public:
	CFileFilter() {
	}

public:
	CFileFilter(const axcl::tstring& sDefaultName) {
		SetDefault(sDefaultName);
	}

public:
	CFileFilter(const axcl::tstring& sDefaultName, const axcl::tstring& sDisplayText) {
		SetDefault(sDefaultName);

		_TCHAR szStarDotPattern[MAX_PATH];
		StringCbPrintf(szStarDotPattern, sizeof szStarDotPattern, _T("*%s"), &CFileFilter::GetDefaultExtension);
		AddFilter(sDisplayText, szStarDotPattern);
	}

public:
	void AddFilter(const axcl::tstring& sDisplayText, const axcl::tstring& sPattern) {
		// They don't make it easy by using nul chars...

		// Build a display text for the filter
		_TCHAR szFilterText[100];
		StringCbPrintf(szFilterText, sizeof szFilterText, _("%s (%s)#%s#"), sDisplayText.c_str(), sPattern.c_str(), sPattern.c_str());

		axcl::tstring sFilter = axcl::tstring(szFilterText);
		for (axcl::tstring::iterator it = sFilter.begin(); it != sFilter.end(); it++) {
			if (*it == _T('#')) {
				*it = _T('\0');
			}
		}
		if (m_sFilter.length() > 0) {
			m_sFilter.erase(m_sFilter.end());
		}
		m_sFilter.append(sFilter);
	}

public:
	const axcl::tstring& GetDefaultName() const {
		return m_sDefaultName;
	}

	const axcl::tstring& GetDefaultExtension() const {
		return m_sDefaultExtension;
	}

	const axcl::tstring& GetFilter()const {
		return m_sFilter;
	}
};

class CKeyFileDialog : public CFileDialog {
	typedef CFileDialog base;
public:

public:
	CKeyFileDialog(const CFileFilter& filter) : base(TRUE,
		filter.GetDefaultExtension().c_str(),
		filter.GetDefaultName().c_str(),
		OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY,
		filter.GetFilter().c_str())
	{
	}
};

/// \brief Handle a Progress dialog
///
/// A progress dialog is expected to be used by one or more operations in sequence,
/// but may not necessarily be displayed at once. Two criteria need to be met for it
/// to be displayed. A timer must be started, and it must expire. The dialog thus is
/// a state-machine with three states:
///
/// 1 - Invisible, i.e. created and all, but not displayed
/// 2 - TimerWait, i.e. waiting for a timer to expire to be enter state 3
/// 3 - Visible, i.e. fully visible and updated.
///
/// When created it enters state 1.
/// To enter state Invisible, send CDlgProgress::WM_APP_PROGRESS(CDlgProgress::Invisible)
/// To enter state TimerWait, send CDlgProgress::WM_APP_PROGRESS(CDlgProgress::TimerWait, length)
/// To enter state Visible, send CDlgProgress::WM_APP_PROGRESS(CDlgProgress::Visible)
///
class CDlgProgress : public CDialogImpl<CDlgProgress> {
	typedef CDialogImpl<CDlgProgress> base;

private:
	bool m_bCancel;

private:
	enum {
		WM_APP_PROGRESS = WM_APP,           ///< Send this to control the display of progress
	};

private:
	/// \brief Define the states of the little state machine
	enum {
		Invisible,                          ///< We're invisible and will stay so until TimerWait
		TimerWait,                          ///< We're invisible, but a timer is running
		Visible,                            ///< We're visible
		Hidden,                             ///< We're hidden and will require explict transition to invisible
	} m_State;

private:
	/// \brief Each timer in Window has an index, this is the one we use here
	static const int m_TimerIndex = 1;

public:
	enum { IDD = IDD_PROGRESS };

private:
	BEGIN_MSG_MAP_EX(CDlgProgress)
		MSG_WM_INITDIALOG(OnInitDialog)
		MSG_WM_CLOSE(OnClose)
		MSG_WM_DESTROY(OnDestroy)
		MSG_WM_TIMER(OnTimer)
		MESSAGE_HANDLER_EX(WM_APP_PROGRESS, OnAppProgress)
		COMMAND_ID_HANDLER_EX(IDCANCEL, OnOKCancel)
		END_MSG_MAP()

private:
	/// The timer has expired, start transitioning to state 'Visible'
	void OnTimer(UINT_PTR wParam) {
		if (wParam == m_TimerIndex) {
			SendMessage(WM_APP_PROGRESS, Visible, 0);
		}
	}

private:
	/// If we have a timer running, we need to kill it when the window is destroyed
	void OnDestroy() {
		if (m_State == TimerWait) {
			KillTimer(m_TimerIndex);
		}
	}

private:
	/// \brief Handle the windows message WM_APP_PROGRESS to transition between the states in the state machine
	LRESULT OnAppProgress(UINT /*uMsg*/, WPARAM wParam, LPARAM lParam) {
		switch (wParam) {
		case Invisible:
			// If state already is invisible we just accept that.
			if (m_State != Invisible) {
				if (m_State == TimerWait) {
					KillTimer(m_TimerIndex);
				}
				if (m_State == Visible) {
					ShowWindow(SW_HIDE);
				}
				if (m_State == Hidden) {
					// do nothing
				}
				m_State = Invisible;
			}
			break;
		case TimerWait:
			if (m_State != TimerWait) {
				if (m_State == Hidden) {
					// Ignore TimerWait in Hidden state
					break;
				}
				m_State = TimerWait;
				SetTimer(m_TimerIndex, static_cast<UINT>(lParam), NULL);
			}
			break;
		case Visible:
			// If state already is Visible we just accept that
			// There's no need to do anything if we're already Visible
			if (m_State != Visible) {
				if (m_State == TimerWait) {
					KillTimer(m_TimerIndex);
				}
				ShowWindow(SW_NORMAL);
				m_State = Visible;
			}
			break;
		case Hidden:
			if (m_State != Hidden) {
				if (m_State == TimerWait) {
					KillTimer(m_TimerIndex);
				}
				if (m_State == Visible) {
					ShowWindow(SW_HIDE);
				}
				m_State = Hidden;
			}
			break;
		default:
			break;
		}
		return TRUE;
	}

private:
	LRESULT OnInitDialog(HWND /*hWnd*/, LPARAM /*lParam*/) {
		m_bCancel = false;
		m_State = Invisible;
		CenterWindow();
		SetMsgHandled(false);
		SetOperation();
		SetDlgItemText(IDCANCEL, _("Cancel"));
		::SetFocus(GetDlgItem(IDCANCEL));
		return TRUE;
	}

private:
	/// \brief Close is the same as cancel
	void OnClose() {
		m_bCancel = true;
	}

private:
	/// \brief There is no OK button, so this can only mean Close
	LRESULT OnOKCancel(UINT /*wNotifyCode*/, int /*wID*/, HWND /*hWndCtl*/) {
		m_bCancel = true;
		return FALSE;
	}

public:
	/// \brief Make the progress window visible in a specified amount of time
	/// \param iMilliSeconds The number of milliseconds to wait before displaying the window
	void StartTimer(int iMilliSeconds) {
		SendMessage(WM_APP_PROGRESS, TimerWait, iMilliSeconds);
	}

public:
	/// \brief Hide the progress window (again). Needs a UnHide() + StartTimer() to become visible again.
	void Hide() {
		SendMessage(WM_APP_PROGRESS, Hidden, 0);
	}

public:
	/// \brief UnHide the progress, making it respond to TimerWait again
	void UnHide() {
		SendMessage(WM_APP_PROGRESS, Invisible, 0);
	}

public:
	/// \brief true if user cancelled in the progress window
	bool IsCancelled() {
		return m_bCancel;
	}

public:
	/// \brief Set the file-name to be displayed during progress
	void SetFileName(LPCTSTR szPath = NULL) {
		if (szPath == NULL || szPath[0] == _T('\0')) {
			SetDlgItemText(IDC_FILENAME, _T(""));
		}
		else {
			SetDlgItemText(IDC_FILENAME, szPath);
		}
	}

public:
	/// \brief Set the "operation"-text, telling the user what is happening with the file
	/// \pram szOperation A short term, typically one word like "Encrypting", describing the operation.
	void SetOperation(LPCTSTR szOperation = NULL) {
		if (szOperation == NULL || szOperation[0] == _T('\0')) {
			SetWindowText(CConfig::ShortProductName().c_str());
		}
		else {
			_TCHAR szTitle[200];
			ASSCHK(SUCCEEDED(StringCbPrintf(szTitle, sizeof szTitle, _("CDialogsWin|%s - %s"), CConfig::ShortProductName().c_str(), szOperation)), _T("StringCbPrintf"));
			SetWindowText(szTitle);
		}
	}
};

template<class T> class CPassphraseBase : public CDialogImpl<T>,
public CWinDataExchange<T>,
protected CPassphraseChars {
	typedef CPassphraseChars base;

protected:
	CString m_Passphrase1;
	CFileFilter m_FileFilter;               ///< Build the file filter info for the KeyFileDialog here
	CKeyFileDialog* m_pdlgKeyFile;          ///< This is the FileOpen standard dialog. Need to be ptr for constructor reasons.

public:
	CPassphraseBase(axcl::CXecretsFileLib* pXecretsFileLib = NULL) : base(pXecretsFileLib), m_pdlgKeyFile(NULL)
	{
		m_FileFilter.SetDefault(_("CKeyFileDialog|My Key File.txt"));
		m_FileFilter.AddFilter(_("CKeyFileDialog|Key Files"), _("CKeyFileDialog|*.txt"));
		m_FileFilter.AddFilter(_("CKeyFileDialog|All files"), _("CKeyFileDialog|*.*"));

		// Now that we have a nice filter, let's construct our key file dialog. We need to have the filter data
		// living and alive for as long as the dialog may exist, since it won't be used until the dialog is actually
		// invoked via DoModal().
		m_pdlgKeyFile = new CKeyFileDialog(m_FileFilter);
	}

public:
	~CPassphraseBase() {
		delete m_pdlgKeyFile;
	}

protected:
	/// \brief Get a pointer to the entered passphrase in it's _TCHAR representation (most likely Unicode UTF-16)
	const _TCHAR* GetPassphrase() {
		return m_Passphrase1;
	}

protected:
	/// \brief Get the Key File Name provided - or a NULL pointer
	const _TCHAR* GetKeyFileName() {
		// Test to see if there's anything in the Key File Name edit box. Only if there is, do we get the name from the
		// FileDialog.
		_TCHAR c[2];
		if (::GetWindowText(GetDlgItem(IDC_EDIT_KEYFILENAME), c, sizeof c / sizeof c[0]) == (sizeof c / sizeof c[0]) - 1) {
			return m_pdlgKeyFile->m_szFileName;
		}
		return NULL;
	}

protected:
	/// \brief Get a pointer to the passphrase in it's Ansi representation - filtered for Ax Crypt 1.x legal chars
	/// \param sPassphrase a pointer to a buffer (or NULL)
	/// \param ccPassphrase the size of the buffer
	/// \return The number of chars needed - if ccPassphrase == 0, sPassphrase is not used
	size_t GetAnsiPassphrase(char* sPassphrase, size_t cbPassphrase) {
		// Init to a very large value, if we by any chance exit this the wrong way
		size_t j = ~size_t(0);
		try {
			// Allocate a too small static buffer, to ensure that malloc is used
			CT2AEX<1> pszPassphrase(m_Passphrase1, CP_ACP);

			// Check if we have a large enough buffer, including null
			size_t cb = strlen(pszPassphrase);
			// Comparing >= accounts for the nul as well
			if (cb >= cbPassphrase) {
				// This and above accounts for the nul
				j = cb + 1;
			}
			else {
				// Filter the result by ensuring only valid passphrase characters are actually returned
				size_t i = 0;
				int c;
				j = 0;
				while (i < cb) {
					if (strchr(m_szPassphraseChars, c = pszPassphrase[i++]) != NULL) {
						sPassphrase[j++] = static_cast<char>(c);
					}
				}
				sPassphrase[j++] = '\0';
			}

			// An extra precaution to clear this buffer as quickly as possible. Should not be strictly
			// necessary, but does not hurt.
			memset(&pszPassphrase[0], 0, cb);
		}
		catch (CAtlException e) {
			ASSCOM(e);
		}
		return j;
	}

public:
	LRESULT OnButtonKeyFile(UINT /*wNotifyCode*/, int /*wID*/, HWND /*hWndCtl*/) {
		if (m_pdlgKeyFile->DoModal() == IDOK) {
			::SetWindowText(GetDlgItem(IDC_EDIT_KEYFILENAME), m_pdlgKeyFile->m_szFileTitle);
		}
		else {
			::SetWindowText(GetDlgItem(IDC_EDIT_KEYFILENAME), _T(""));
		}
		return TRUE;
	}

public:
	BEGIN_MSG_MAP_EX(CPassphraseBase<T>)
		COMMAND_ID_HANDLER_EX(IDC_BTN_KEYFILE, OnButtonKeyFile)
		END_MSG_MAP()
};

class CEncryptPassphrase : public CPassphraseBase<CEncryptPassphrase> {
	typedef CPassphraseBase<CEncryptPassphrase> base;

public:
	CEncryptPassphrase(axcl::CXecretsFileLib* pXecretsFileLib = NULL) : base(pXecretsFileLib) {
	}

protected:
	class CMyEdit : public CWindowImpl<CMyEdit, CEdit> {
		BEGIN_MSG_MAP_EX(CMyEdit)
		END_MSG_MAP()
	};

	CString m_Passphrase2;

	BOOL DDX_Text(UINT nID, CString& strText, int cbSize, BOOL bSave, BOOL bValidate = FALSE, int nLength = 0) {
		BOOL bSuccess = CWinDataExchange<CEncryptPassphrase>::DDX_Text(nID, strText, cbSize, bSave, bValidate, nLength);
		// If the default validation succeeded, let's add our own...
		if (nID == IDC_EDIT_PASSPHRASE_2) {
			// Always validate on save
			if (bSuccess && bSave) {
				if (_tcscmp(m_Passphrase1, m_Passphrase2) != 0) {
					_XData data = { ddxDataText };
					data.textData.nLength = strText.GetLength();
					data.textData.nMaxLength = nLength;
					OnDataValidateError(nID, bSave, data);
					bSuccess = FALSE;
				}
				else {
					// Find the necessary size, allocate a buffer, and get the passphrase in it's Ansi representatino
					size_t cbPassphrase = GetAnsiPassphrase(NULL, 0);
					std::auto_ptr<char> sPassphrase(new char[cbPassphrase]);
					ASSCHK(GetAnsiPassphrase(sPassphrase.get(), cbPassphrase) <= cbPassphrase, _T("GetAnsiPassphrase() buffer too small"));

					ASSCHK(m_pXecretsFileLib->HashKey(AXCL_KEY_ENC, reinterpret_cast<const unsigned char*>(sPassphrase.get()), strlen(sPassphrase.get()), GetKeyFileName()) == AXCL_E_OK, m_pXecretsFileLib->GetError().c_str());
				}
			}
		}
		return bSuccess;
	}

public:
	void OnDataValidateError(UINT /*nCtrlId*/, BOOL /*bSave*/, _XData& /*data*/) {
		MessageBox(_("Passphrase mismatch or other error"), CConfig::ShortProductName().c_str(), MB_ICONEXCLAMATION);
		m_Passphrase1.Empty();
		m_Passphrase2.Empty();
		DoDataExchange(DDX_LOAD);
		::SetFocus(GetDlgItem(IDC_EDIT_PASSPHRASE_1));
	}

	enum { IDD = IDD_ENCRYPT_PASSPHRASE };

	BEGIN_DDX_MAP(CEncryptPassphrase)
		DDX_TEXT(IDC_EDIT_PASSPHRASE_1, m_Passphrase1);
	DDX_TEXT(IDC_EDIT_PASSPHRASE_2, m_Passphrase2);
	END_DDX_MAP()

	BEGIN_MSG_MAP_EX(CEncryptPassphrase)
		MSG_WM_INITDIALOG(OnInitDialog)
		MSG_WM_CLOSE(OnClose)
		COMMAND_ID_HANDLER_EX(IDOK, OnOKCancel)
		COMMAND_ID_HANDLER_EX(IDCANCEL, OnOKCancel)
		CHAIN_MSG_MAP(base)
		END_MSG_MAP()

	LRESULT OnInitDialog(HWND /*hWnd*/, LPARAM /*lParam*/) {
		SetDlgItemText(IDC_STATIC_ENTER_PASSPHRASE, _("CEncryptPassphrase|Enter a passphrase and optionally a key-file"));
		SetDlgItemText(IDC_STATIC_GRP_PASSPHRASE, _("CEncryptPassphrase|Passphrase"));
		SetDlgItemText(IDC_STATIC_VERIFY, _("CEncryptPassphrase|Verify"));
		SetDlgItemText(IDC_STATIC_GRP_KEYFILE, _("CEncryptPassphrase|Key-file"));
		SetDlgItemText(IDC_STATIC_CHK_CACHE_D, _("CEncryptPassphrase|Retain for decryption during session"));
		SetDlgItemText(IDC_STATIC_CHK_CACHE_E, _("CEncryptPassphrase|Session default for encryption"));
		SetDlgItemText(IDOK, _("StandardWindowsButtonText|OK"));
		SetDlgItemText(IDCANCEL, _("StandardWindowsButtonText|Cancel"));
		SetWindowText(CConfig::ShortProductName().c_str());

		CenterWindow();
		SetMsgHandled(false);
		DoDataExchange(DDX_LOAD);
		::SetFocus(GetDlgItem(IDC_EDIT_PASSPHRASE_1));
		return TRUE;
	}

	void OnClose() {
		EndDialog(IDCANCEL);
	}

	LRESULT OnOKCancel(UINT /*wNotifyCode*/, int wID, HWND /*hWndCtl*/) {
		if (wID == IDOK && !DoDataExchange(DDX_SAVE)) {
			return TRUE;
		}
		else {
			EndDialog(wID);
			return FALSE;
		}
	}
};

class CDecryptPassphrase : public CPassphraseBase<CDecryptPassphrase> {
	typedef CPassphraseBase<CDecryptPassphrase> base;

public:
	CDecryptPassphrase(axcl::CXecretsFileLib* pXecretsFileLib = NULL) : base(pXecretsFileLib) {
	}

protected:

	BOOL DDX_Text(UINT nID, CString& strText, int cbSize, BOOL bSave, BOOL bValidate = FALSE, int nLength = 0) {
		BOOL bSuccess = CWinDataExchange<CDecryptPassphrase>::DDX_Text(nID, strText, cbSize, bSave, bValidate, nLength);

		// Always validate here...
		if (bSuccess && bSave) {
			// Find the necessary size, allocate a buffer, and get the passphrase in it's Ansi representatino
			size_t cbPassphrase = GetAnsiPassphrase(NULL, 0);
			std::auto_ptr<char> sPassphrase(new char[cbPassphrase]);
			ASSCHK(GetAnsiPassphrase(sPassphrase.get(), cbPassphrase) <= cbPassphrase, _T("GetAnsiPassphrase() buffer too small"));

			ASSCHK(m_pXecretsFileLib->HashKey(AXCL_KEY_DEC, reinterpret_cast<const unsigned char*>(sPassphrase.get()), strlen(sPassphrase.get()), GetKeyFileName()) == AXCL_E_OK, m_pXecretsFileLib->GetError().c_str());
			// Check the key and get the decrypted meta-data
			int iError = m_pXecretsFileLib->DecryptFileMeta(AXCL_KEY_DEC, m_pXecretsFileLib->GetThisCipherPath().c_str());
			if (iError != AXCL_E_OK) {
				// Ensure that it really was the key, and not something else.
				ASSCHK(iError == AXCL_E_WRONGKEY, m_pXecretsFileLib->GetError().c_str());

				_XData data = { ddxDataText };
				data.textData.nLength = strText.GetLength();
				data.textData.nMaxLength = nLength;
				OnDataValidateError(nID, bSave, data);
				bSuccess = FALSE;
			}
		}

		return bSuccess;
	}

public:
	void OnDataValidateError(UINT /*nCtrlId*/, BOOL /*bSave*/, _XData& /*data*/) {
		MessageBox(_("Incorrect passphrase"), CConfig::ShortProductName().c_str(), MB_ICONEXCLAMATION);
		m_Passphrase1.Empty();
		DoDataExchange(DDX_LOAD);
		::SetFocus(GetDlgItem(IDC_EDIT_PASSPHRASE_1));
	}

public:

	enum { IDD = IDD_DECRYPT_PASSPHRASE };

	BEGIN_DDX_MAP(CDecryptPassphrase)
		DDX_TEXT(IDC_EDIT_PASSPHRASE_1, m_Passphrase1);
	END_DDX_MAP()

	BEGIN_MSG_MAP_EX(CDecryptPassphrase)
		MSG_WM_INITDIALOG(OnInitDialog)
		MSG_WM_CLOSE(OnClose);
	COMMAND_ID_HANDLER_EX(IDOK, OnOKCancel)
		COMMAND_ID_HANDLER_EX(IDCANCEL, OnOKCancel)
		CHAIN_MSG_MAP(base)
		END_MSG_MAP()

	LRESULT OnInitDialog(HWND /*hWnd*/, LPARAM /*lParam*/) {
		SetDlgItemText(IDC_STATIC_ENTER_PASSPHRASE, _("CDecryptPassphrase|Enter a passphrase and optionally a key-file"));
		SetDlgItemText(IDC_STATIC_GRP_PASSPHRASE, _("CDecryptPassphrase|Passphrase"));
		SetDlgItemText(IDC_STATIC_GRP_KEYFILE, _("CDecryptPassphrase|Key-file"));
		SetDlgItemText(IDC_STATIC_CHK_CACHE_D, _("CDecryptPassphrase|Retain for decryption during session"));
		SetDlgItemText(IDC_STATIC_CHK_CACHE_E, _("CDecryptPassphrase|Session default for encryption"));
		SetDlgItemText(IDOK, _("StandardWindowsButtonText|OK"));
		SetDlgItemText(IDCANCEL, _("StandardWindowsButtonText|Cancel"));
		SetWindowText(CConfig::ShortProductName().c_str());

		CenterWindow();
		SetMsgHandled(false);
		DoDataExchange(DDX_LOAD);
		::SetFocus(GetDlgItem(IDC_EDIT_PASSPHRASE_1));
		return TRUE;
	}

	void OnClose() {
		EndDialog(IDCANCEL);
	}

	LRESULT OnOKCancel(UINT /*wNotifyCode*/, int wID, HWND /*hWndCtl*/) {
		if (wID == IDOK && !DoDataExchange(DDX_SAVE)) {
			return TRUE;
		}
		else {
			EndDialog(wID);
			return FALSE;
		}
	}
};

class CAboutDlg : public CDialogImpl<CAboutDlg> {
public:
	enum { IDD = IDD_ABOUTBOX };

	BEGIN_MSG_MAP(CAboutDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		MESSAGE_HANDLER(WM_CLOSE, OnClose)
		COMMAND_ID_HANDLER(IDC_GETAXCRYPT, OnGetAxCrypt);
	COMMAND_ID_HANDLER(IDOK, OnOKCancel)
		COMMAND_ID_HANDLER(IDCANCEL, OnOKCancel)
	END_MSG_MAP()

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		AxLib::CVersion ver;
		_TCHAR szMsg[1024], * szNameVersion = ver.newNameVersionString();

		StringCbPrintf(szMsg, sizeof szMsg, _("About %s"), szNameVersion);
		SetWindowText(szMsg);
		delete[] szNameVersion;

		_TCHAR* sz;
		ASSPTR(sz = ver.newLegalCopyright());
		SetDlgItemText(IDC_COPYRIGHT, sz);
		delete[] sz;

		StringCbPrintf(szMsg, sizeof szMsg, _("This is an ALPHA-version! Pre-BETA! Enjoy, but be aware, and please report problems and suggestions! Get the full version of %s for one-click encryption, decryption and viewing."), _("GlobalNames|AxCrypt"));
		SetDlgItemText(IDC_ABOUTMSG, szMsg);

		SetDlgItemText(IDC_GETAXCRYPT, _("http://www.axantum.com"));

		CenterWindow();
		return TRUE;    // let the system set the focus
	}

	LRESULT OnGetAxCrypt(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/) {
		_TCHAR szURL[200];
		UINT cc = GetDlgItemText(IDC_GETAXCRYPT, szURL, sizeof szURL / sizeof szURL[0]);

		// If the URL for whatever reason is *that* long, let's just silently skip. No real harm done.
		if (cc < sizeof szURL / sizeof szURL[0]) {
			ShellExecute(m_hWnd, NULL, szURL, NULL, NULL, SW_NORMAL);
		}
		return TRUE;
	}

	LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		EndDialog(IDCANCEL);
		return 0;
	}

	LRESULT OnOKCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		EndDialog(wID);
		return 0;
	}
};

#endif // CDIALOGSWIN_H