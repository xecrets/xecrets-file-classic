/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2020 Svante Seleborg/Axon Data, All rights reserved.

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
	ShellExtension.cpp				The shell extension object implementation

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include "stdafx.h"
#include "XecretsFileShellExt.h"

#include <assert.h>

//
// Define (not declare) the Xecrets File GUID
//
#pragma data_seg(".text")
#define INITGUID
#include <initguid.h>
#include <shlguid.h>
#include "../XecretsFileCommon/XecretsFileGUID.h"
#pragma data_seg()

#include "../XecretsFileCommon/CRegistry.h"
#include "../XecretsFileCommon/CFileName.h"
#include "../XecretsFileCommon/Utility.h"
#include "../XecretsFileCommon/CVersion.h"
#include "../AxPortLib/ttstring.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "ShellExt.cpp"

//
// Global variables
//
long glRefThisDLL = 0;						// The DLL reference count
HINSTANCE ghInstance = NULL;				// A handle to the DLL
CHModule ghMsgModule = NULL;    			// Needed for messages and logevents.
HBITMAP ghBitmap = NULL;					// A handle for the bitmap used in the menu
CRITICAL_SECTION gInitCritical;             // Needed for init / uninit
IMalloc* gpMalloc = NULL;

BOOL glServerMode = FALSE;

// This must just exist - we construct and destruct in DllMain
AxPipe::CGlobalInit* pAxPipeGlobalInit = NULL;

BOOL APIENTRY
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
	const _TCHAR* szMsg;

	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		CVersion::Init(hInstance);
		InitializeCriticalSection(&gInitCritical);
		pAxPipeGlobalInit = new AxPipe::CGlobalInit();
		szMsg = InitGlobalStrings(ghInstance = hInstance);
		if (szMsg != NULL) {
			MessageBox(NULL, szMsg, CFileName().SetPath2ExeName(ghInstance).GetTitle(), MB_OK);
			return FALSE;
		}
		glServerMode = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE);
		break;
	case DLL_PROCESS_DETACH:
		// Clean up the AxPipe global object.
		if (pAxPipeGlobalInit) {
			delete pAxPipeGlobalInit;
			pAxPipeGlobalInit = NULL;
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

STDAPI
DllCanUnloadNow(void) {
	if (glRefThisDLL > 0) {
		return S_FALSE;
	}
	else {
		// No more references to the dll, release the library and the malloc ref
		if (gpMalloc != NULL) gpMalloc->Release();
		gpMalloc = NULL;

		if ((HMODULE)ghMsgModule != NULL) FreeLibrary(ghMsgModule);
		ghMsgModule = NULL;

		if (ghBitmap != NULL) DeleteBitmap(ghBitmap);
		ghBitmap = NULL;

		return S_OK;
	}
}

STDAPI
DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppvOut) {
	*ppvOut = NULL;

	GUID clsidAxCrypt;
	auto_ptr<wchar_t> wzCLSID(_wcsdup(axpl::t2ws((TCHAR*)gszAxCryptCLSID).c_str()));
	CLSIDFromString(wzCLSID.get(), &clsidAxCrypt);

	if (IsEqualIID(rclsid, clsidAxCrypt)) {
		//MessageBox(NULL, _T("returning new cshellextclassfactory"), _T("DllGetClassObject"), MB_OK);
		CShellExtClassFactory* pcf = new CShellExtClassFactory;
		ASSPTR(pcf);

		return pcf->QueryInterface(riid, ppvOut);
	}
	return CLASS_E_CLASSNOTAVAILABLE;
}

void
IncrementDllReference() {
	// Theoretically a context switch could occur here, thus the need for the
	// critical section. Or maybe not - I'm not 100% clear on the threading
	// model used and the implications here.
	CCriticalSection utInitCritical(&gInitCritical, TRUE);

	//MessageBox(NULL, _T("Incrementing"), _T("CShellExt DLL"), MB_OK);
	InterlockedIncrement(&glRefThisDLL);
	if (gpMalloc == NULL) {
		(void)SHGetMalloc(&gpMalloc); // Initialize pointer to shell malloc
		if (gpMalloc == NULL) {
			FatalAppExit(0, _T("Failed to get Shell IMalloc interface. Immediate exit."));
		}
	}

	if (ghMsgModule == NULL) {
		if (!(ghMsgModule = LoadLibraryEx(
			CFileName().SetPath2ExeName(ghInstance).SetTitle((LPTSTR)gszAxCryptMessageDLL).Get(),
			NULL,
			LOAD_LIBRARY_AS_DATAFILE)).IsValid()) {
			FatalAppExit(0, _T("Failed to load application texts. Immediate exit."));
		}
	}
}

void
DecrementDllReference() {
	// Theoretically a context switch could occur here, thus the need for the
	// critical section.
	CCriticalSection utInitCritical(&gInitCritical, TRUE);

	if (!InterlockedDecrement(&glRefThisDLL)) {
	}
}

CShellExtClassFactory::CShellExtClassFactory() {
	IncrementDllReference();
	m_cRef = 0;
}

CShellExtClassFactory::~CShellExtClassFactory() {
	DecrementDllReference();
}

STDMETHODIMP
CShellExtClassFactory::QueryInterface(REFIID iid, void** ppvObject) {
	*ppvObject = NULL;

	// Accept requests for both IUnknown and IClassFactory
	if (IsEqualIID(iid, IID_IUnknown) || IsEqualIID(iid, IID_IClassFactory)) {
		*ppvObject = (LPCLASSFACTORY)this;
		AddRef();
		return NOERROR;
	}
	return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG)
CShellExtClassFactory::AddRef() {
	return ++m_cRef;
}

STDMETHODIMP_(ULONG)
CShellExtClassFactory::Release() {
	if (--m_cRef) return m_cRef;
	delete this;
	return 0;
}

STDMETHODIMP
CShellExtClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
	*ppvObject = NULL;

	// Don't support aggregation
	if (pUnkOuter != NULL) return CLASS_E_NOAGGREGATION;

	// Create our object, the shell will call us for init through the IShellExtInit
	// interface.
	LPCSHELLEXT pShellExt = new CShellExt();
	if (pShellExt == NULL) return E_OUTOFMEMORY;

	return pShellExt->QueryInterface(riid, ppvObject);
}

STDMETHODIMP
CShellExtClassFactory::LockServer(BOOL fLock) {
	return NOERROR;		// Nothing happens
}

CShellExt::CShellExt() {
	IncrementDllReference();

	m_cRef = 0;
	m_hMenu = NULL;
	m_szBatch = NULL;
	m_pSelection = new CFileObjectList;
	ASSPTR(m_pSelection);

	SetBatch(m_iBatch = 0);
}

CShellExt::~CShellExt() {
	if (m_hMenu != NULL) DestroyMenu(m_hMenu);
	if (m_szBatch != NULL) delete m_szBatch;
	if (m_pSelection != NULL) delete m_pSelection;

	DecrementDllReference();
}

STDMETHODIMP
CShellExt::QueryInterface(REFIID iid, void** ppvObject) {
	*ppvObject = NULL;

	// If we are in server mode - no right click!
	if (!glServerMode) {
		if (IsEqualIID(iid, IID_IShellExtInit) || IsEqualIID(iid, IID_IUnknown)) {
			*ppvObject = (LPSHELLEXTINIT)this;
		}
		else if (IsEqualIID(iid, IID_IContextMenu)) {
			*ppvObject = (LPCONTEXTMENU)this;
		}
		else if (IsEqualIID(iid, IID_IShellPropSheetExt)) {
			*ppvObject = (LPSHELLPROPSHEETEXT)this;
		}
	}

	if (*ppvObject) {
		AddRef();
		return NOERROR;
	}
	return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG)
CShellExt::AddRef() {
	return ++m_cRef;
}

STDMETHODIMP_(ULONG)
CShellExt::Release() {
	if (--m_cRef) return m_cRef;
	delete this;
	return 0;
}

#ifndef	_DEBUGHEAP
#ifdef	_DEBUG
__declspec(thread) size_t stAcceptedLeak = 0;

CHeapCheck::CHeapCheck(LPTSTR szFunc, BOOL fLeakOk) {
	// Do nothing in the shell extension
}

CHeapCheck::~CHeapCheck() {
	// Do noting in the shell extension
}
#endif	_DEBUG
#endif	_DEBUGHEAP