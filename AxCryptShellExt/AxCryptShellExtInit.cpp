/*
    @(#) $Id: ShellExtInit.cpp 1401 2008-04-15 16:35:34Z svante $

	Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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
	ShellExtensionInit.cpp			IShellExtInit implementation

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
                                    2002-08-07              Rel 1.2

*/
#include "StdAfx.h"
//
//	Initializes a property sheet extension, context menu extension, or drag-and-drop handler.
//
//	Returns NOERROR if successful, or an OLE-defined error value otherwise.
//	pidlFolder
//		Address of an ITEMIDLIST structure that uniquely identifies a folder.
//		For property sheet extensions, this parameter is NULL. For context menu extensions,
//		it is the item identifier list for the folder that contains the item whose context
//		menu is being displayed. For nondefault drag-and-drop menu extensions,
//		this parameter specifies the target folder. (This seems to be untrue - I get
//      no pidl to folder for my context menu extension... :-( /SS).
//	lpdobj
//		Address of anIDataObject interface object that can be used to retrieve
//		the objects being acted upon.
//	hkeyProgID
//		Registry key for the file object or folder type.
//
STDMETHODIMP
CShellExt::Initialize(LPCITEMIDLIST pidlFolder, IDataObject *pdObj, HKEY hkeyProgID) {
    try {
        m_pSelection->SetObject(pdObj);      // Save the selection object reference for later
    } catch (TAssert utErr) {
        utErr.Show();
        return E_UNEXPECTED;
    }
    return NOERROR;
}