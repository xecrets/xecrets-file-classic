#pragma once

/*
	@(#) $Id$

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
	StdAfx.h						Precompiled header file

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

// C++ exception specification ignored except to indicate a function is not __declspec(nothrow)
// A function is declared using exception specification, which Visual C++ accepts but does not
// implement. Code with exception specifications that are ignored during compilation may need
// to be recompiled and linked to be reused in future versions supporting exception specifications.
// (This is an improvement from VC6 - Now they not only don't support it - they cause a valid program
//  to report warnings!!!)
#pragma warning( disable : 4290 )

#include "targetver.h"

#define	STRICT
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define OEMRESOURCE
#define	INC_OLE2				// Let windows.h include OLE-stuff
#define _CRT_RAND_S
// Windows Header Files:
#include <windows.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

// TODO: reference additional headers your program requires here
#include <winioctl.h>                       // Include here to avoid namespace collission for BOOLEAN with CryptoPP
#include <lm.h>                             // Include here to avoid namespace collission for BOOLEAN with CryptoPP
#include <stdio.h>
#include <shlobj.h>

// Generated includes
#include "resource.h"

//
// Ax Crypt common includes
//
#include "../XecretsFileCommon/Oem.h"
#include "../XecretsFileCommon/Types.h"
#include "XecretsFileTexts.h"
#include "../XecretsFileCommon/AxCommon.h"
#include "XecretsFile.h"
#include "AxConfig.h"
#include "../XecretsFileCommon/Utility.h"
#include "../XecretsFileCommon/CAssert.h"
#include "../XecretsFileCommon/CStrPtr.h"

#include "../AxPipe/AxPipe.h"