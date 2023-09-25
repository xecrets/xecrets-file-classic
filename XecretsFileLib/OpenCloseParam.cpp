/*! \file
	\brief OpenCloseParam.cpp - Open and Close the XecretsFileLib parameter block

	@(#) $Id$

	OpenCloseParam.cpp - Open and Close the XecretsFileLib parameter block

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-10-28              Initial
\endverbatim
*/
#include "stdafx.h"

extern "C" {
#include "XecretsFileLib.h"
}
#include "XecretsFileLibPP.h"
#include "BlockTypes.h"

#include "Assert.h"
#define ASSERT_FILE "OpenCloseParam.cpp"

/// \brief Allocate and initialize a parameter block
/// \param pfCallback The pointer to the callback to use
/// \param pContext The caller context to store for use by the caller in the callback
/// \return An initialized parameter block
AXCL_PARAM* axcl_Open(AXCL_CALLBACK pfCallback, void* pContext) {
	AXCL_PARAM* pParam = new AXCL_PARAM;
	memset(pParam, 0, sizeof * pParam);

	pParam->cbChunkSize = AXCL_CHUNK_SIZE;
	pParam->iZipMinSaveRatio = AXCL_ZIP_SAVE_RATIO;
	pParam->pCallbackContext = pContext;
	pParam->pfCallback = pfCallback;

	// Ensure there is an error message
	pParam->strBufs[AXCL_STR_ERRORMSG] = axcl::tstrdup(_TT("No error"));

	// Pre-allocate the memory for the keys
	int i;
	for (i = 0; i < AXCL_KEY_N; i++) {
		pParam->keys[i].pFingerprint = new unsigned char[sizeof(axcl::TFingerprint)];
		pParam->keys[i].cbFingerprint = sizeof(axcl::TFingerprint);
		pParam->keys[i].pKEK = new unsigned char[sizeof(axcl::TKey)];
		pParam->keys[i].cbKEK = sizeof(axcl::TKey);
	}

	return pParam;
}

/// \brief Free all memory resources associated with the provided parameter block
/// \param pParam The parameter block to free. The pointer is invalid after the call.
void axcl_Close(AXCL_PARAM* pParam) {
	int i;

	// Free all memory for the string buffers
	for (i = 0; i < AXCL_STR_N; i++) {
		delete[] pParam->strBufs[i];
	}

	// Free all memory for the keys
	for (i = 0; i < AXCL_KEY_N; i++) {
		delete[] pParam->keys[i].pFingerprint;
		delete[] pParam->keys[i].pKEK;
	}

	delete pParam;
}