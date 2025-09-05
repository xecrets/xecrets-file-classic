#ifndef	_PASSPHRASE
#define	_PASSPHRASE
/*! \file
	\brief Declarations for passphrase dialog

	@(#) $Id$

	Xecrets File Classic/AxDecrypt et. al - Common definitions for passphrase handling

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
---
*/
extern const char szPassphraseChars[];

// The standard says 6, we increase it a bit.
#define	KEY_WRAP_ITERATIONS	10000			///< The number of default iterations we wrap keys in

/// \brief Sub class an edit control, to keep chars out of memory
///
/// A sub-classing of a simple edit-control, so as to keep passphrase
/// chars in memory under this programs control, via 'new'. If 'new' is
/// overridden to provide secure memory, then the passphrase is never
/// stored in 'open' memory, as it will be if we use a regular edit control.
/// We also handle mapping from Unicode to Ansi, as passphrases in Xecrets File Classic
/// always are in Ansi.
class CSafeEdit {
	char* m_szPassphrase;                   ///< The passphrase to return
	size_t m_cbLen;                         ///< The length of the passphrase
	WNDPROC m_lpfnOldWndProc;               ///< Pointer to the 'real' window proc
	BOOL m_fIsWindowUnicode;			    ///< true if chars received are in Unicode.
	BOOL m_fIsPasting;                      ///< true during paste operation.

	/// \brief The actual sub classing window procedure
	static LRESULT CALLBACK SafeEdit(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
public:
	/// \brief Sub class the window class and initialize member variables
	CSafeEdit() {
		ASSPTR(m_szPassphrase = new char[m_cbLen = 50]);
		m_szPassphrase[0] = '\0';
		m_fIsPasting = FALSE;
	}

	/// \brief Subclass and setup userdata pointer etc
	///
	/// \param hEdit Handle to the edit control to sub class
	void Init(HWND hEdit) {
#pragma warning ( push )
#pragma warning ( disable : 4244 4312 )
		m_lpfnOldWndProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)SafeEdit);
		SetWindowLongPtr(hEdit, GWLP_USERDATA, (LONG_PTR)this);
#pragma warning ( pop )
		m_fIsWindowUnicode = IsWindowUnicode(hEdit);
	}

	/// \brief deallocate memory for the passphrase
	~CSafeEdit() {
		delete m_szPassphrase;
	}

	/// \brief Get the passphrase
	/// \return A pointer to the buffer owned by the class. Don't delete.
	char* Passphrase() { return m_szPassphrase; }
};

/// \brief Handle an passphrase dialog
class CAxPassphrase {
	CSafeEdit* m_pSafeEdit;                 ///< Pointer to the sub class control
	auto_ptr<_TCHAR> m_szKeyFileName;       ///< Optional name of key file
	HINSTANCE m_hInstance;                  ///< Handle to our instance
	HWND m_hWndParent;                      ///< Handle to our parent
	bool m_fMoreCancel;                     ///< Set to true to get 'More...' instead of Cancel-button
private:
	/// \brief The actual dialog proc
	static INT_PTR WINAPI DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
public:
	/// \brief Initialize member variables and get instance handle if necessary
	/// \param hWndParent Handle to parent
	/// \param hInstance If NULL, we get the current module instance handle
	CAxPassphrase(HWND hWndParent = NULL, HINSTANCE hInstance = NULL) {
		m_pSafeEdit = NULL;
		m_hInstance = hInstance ? hInstance : GetModuleHandle(NULL);
		m_hWndParent = hWndParent;
		m_szKeyFileName = auto_ptr<_TCHAR>(NULL);
		m_fMoreCancel = false;
	}

	/// \brief delete the sub-class control
	~CAxPassphrase() {
		delete m_pSafeEdit;
	}

	/// \brief Display the dialog
	INT_PTR Show();

	/// \brief Enable More... button
	/// \param fEnable set to true to get 'More..', false to get 'Cancel'.
	void MoreInstead(bool fEnable) {
		m_fMoreCancel = fEnable;
	}

	/// \brief Get a pointer to the passphrase
	/// \return A class-owned pointer to the passphrase, don't delete.
	char* Passphrase() {
		return m_pSafeEdit ? m_pSafeEdit->Passphrase() : "";
	}

	/// \brief Get a pointer to the key file name
	/// \return A class-owned pointer to the passphrase (or NULL), don't delete.
	_TCHAR* KeyFileName() {
		return m_szKeyFileName.get();
	}
};
#endif