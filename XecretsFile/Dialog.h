#ifndef	_DIALOG
#define	_DIALOG
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
	Dialog.h						Secure dialog procedures, handling password entry etc.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include <memory>
using namespace std;

// Get the dialog title bar to use.
extern axpl::ttstring MainDlgTitleBar(HINSTANCE hInstance = NULL);
//
//	Dialog functions
//
bool GetNewPassphrase(char** szPassphrase, TCHAR** szKeyFileName, HWND hWnd = NULL);
bool GetPassphrase(int iPromptID, LPCTSTR szFileName, auto_ptr<char>& szPassphrase, auto_ptr<TCHAR>& szKeyFileName, HWND hWnd = NULL);
bool WarningDlg(LPCTSTR szFileName, DWORD dwMsg, DWORD dwNotAgainMsg, BOOL& fNotAgain);
void FlashBox();
#endif	_DIALOG