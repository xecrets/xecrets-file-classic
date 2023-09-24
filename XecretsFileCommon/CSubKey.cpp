/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

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
	CSubKey.cpp						Generate subkeys from a master key.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
//
//	Generate subkeys for various uses. This class has two main purposes:
//
//	1 - to avoid conflicts caused by using the same subkey in different contexts.
//	2 - to isolate knowledge of relationship between key-size and block-size.
//
//	Exposing one or more subkeys must not endanger either the other subkeys, or the
//	master key. In fact, the eValidator key is exposed in the file, and never used
//	for actual encryption.
//
//	We actually do is to encrypt constants using the master key, until we get enough
//	bits for a key.
//
#include	"stdafx.h"
#include	"CSubKey.h"
#include	"CAes.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CSubKey.cpp"

CSubKey::CSubKey() {
	m_pSubKey = new TKey;
	ASSPTR(m_pSubKey);
}

CSubKey::~CSubKey() {
	delete m_pSubKey;
}

CSubKey&
CSubKey::Set(TKey* pMasterKey, etSubKey eSubKey) {
	TBlock utSubKeyData(eSubKey);
	CAes utCAesCtx(pMasterKey, CAes::eECB, CAes::eEncrypt);

	// We know that a TBlock and a TKey is of the same size... Change here if this
	// changes, or you want to write solid code...
	utCAesCtx.Xblock(&utSubKeyData, (TBlock*)m_pSubKey);

	return *this;
}

TKey*
CSubKey::Get() {
	return m_pSubKey;
}