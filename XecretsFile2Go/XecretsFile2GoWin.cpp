/*! \file
	\brief XecretsFile2GoWin.cpp - The Windows implementation of XecretsFile2Go

	This code builds heavily on the sample code distributed with Windows Template Library,
	which does not name any contributor or author, nor specify any kind of restrictions of
	use. Whilst this particular file is in this form licensed under GNU GPL as per below,
	this is not an attempt to claim authorship of that original code. The intention is only
	to protect the modified work as it is published here.

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Xecrets File Classic for the road.

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

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-08-06              Initial
\endverbatim
*/

#include "stdafx.h"

#include "resource.h"

#include "CShellMgrWin.h"
#include "XecretsFile2GoWin.h"
#include "CMainFrameWin.h"
#include "EncDecWin.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "XecretsFile2GoWin.cpp"

/// The reinterpret_casts in this function is just to get the compiler to swallow it in various cases
#pragma warning(disable:4172)
const _TCHAR*
GetComMsg(HRESULT hr) {
	// Since this is only intended to be called for fatal failed asserts, including
	// memory allocation, we preallocate a fixed size buffer here.
	static _TCHAR szMsg[1024];

	// Get the COM error message
	_tcsncpy_s(szMsg, sizeof szMsg / sizeof szMsg[0], _com_error(hr).ErrorMessage(), sizeof szMsg / sizeof szMsg[0] - 1);

	// Ensure that it is nul-terminated.
	szMsg[sizeof szMsg / sizeof szMsg[0] - 1] = _T('\0');

	return szMsg;
}
#pragma warning(default:4172)

CMyAppModule _Module;

axcl::tstring g_sAxCryptExtension;          ///< The extension, if any, to use for encrypted files

class CThreadManager {
public:
	// thread init param
	struct _RunData {
		LPTSTR lpstrCmdLine;
		int nCmdShow;
	};

	// thread proc
	static DWORD WINAPI MainFrameThreadProc(void* lpData) {
		CMessageLoop theLoop;
		_Module.AddMessageLoop(&theLoop);

		_RunData* pData = reinterpret_cast<_RunData*>(lpData);
		CMainFrame wndFrame;

		ASSCHK(wndFrame.CreateEx() != NULL, _T("Frame window creation failed!"));

		wndFrame.ShowWindow(pData->nCmdShow);
		::SetForegroundWindow(wndFrame);    // Win95 needs this
		delete pData;

		int nRet = theLoop.Run();

		_Module.RemoveMessageLoop();
		return nRet;
	}

	// thread proc
	static DWORD WINAPI WorkerThreadProc(LPVOID lpParam) {
		WorkerThreadParam* pWorkerThreadParam = reinterpret_cast<WorkerThreadParam*>(lpParam);

		_Module.AddWorker();
		DWORD nRet = pWorkerThreadParam->ThreadFunc(pWorkerThreadParam);
		_Module.SubWorker();

		delete pWorkerThreadParam;
		return nRet;
	}

	DWORD m_dwCount;
	HANDLE m_arrThreadHandles[MAXIMUM_WAIT_OBJECTS - 1];

	CThreadManager() : m_dwCount(0) {
	}

	DWORD AddThread(void* pParam, LPTHREAD_START_ROUTINE pfThreadProc) {
		ASSCHK(m_dwCount != (MAXIMUM_WAIT_OBJECTS - 1), _T("CThreadManager::AddThread() Cannot create any more threads!"));

		DWORD dwThreadID;
		HANDLE hThread = ::CreateThread(NULL, 0, pfThreadProc, pParam, 0, &dwThreadID);
		ASSAPI(hThread != NULL);

		m_arrThreadHandles[m_dwCount] = hThread;

		m_dwCount++;
		return dwThreadID;
	}

	/// \brief Add a worker thread for encryption, decryption
	DWORD AddWorkerThread(void* pParam) {
		return AddThread(pParam, WorkerThreadProc);
	}

	/// \brief Add a MainFrame thread, showing the full user interface
	DWORD AddMainFrameThread(LPTSTR lpstrCmdLine, int nCmdShow) {
		ASSCHK(m_dwCount != (MAXIMUM_WAIT_OBJECTS - 1), _T("CThreadManager::AddThread() Cannot create any more threads!"));

		_RunData* pData = new _RunData;
		pData->lpstrCmdLine = lpstrCmdLine;
		pData->nCmdShow = nCmdShow;

		return AddThread(pData, MainFrameThreadProc);
	}

	void RemoveThread(DWORD dwIndex) {
		if (dwIndex != (m_dwCount - 1)) {
			m_arrThreadHandles[dwIndex] = m_arrThreadHandles[m_dwCount - 1];
		}
		m_dwCount--;
	}

	int Run(LPTSTR lpstrCmdLine, int nCmdShow) {
		MSG msg;
		// force message queue to be created
		::PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

		AddMainFrameThread(lpstrCmdLine, nCmdShow);

		int nRet = m_dwCount;
		DWORD dwRet;
		while (m_dwCount > 0) {
			dwRet = ::MsgWaitForMultipleObjects(m_dwCount, m_arrThreadHandles, FALSE, INFINITE, QS_ALLINPUT);
			ASSAPI(dwRet != WAIT_FAILED);

			if (dwRet >= WAIT_OBJECT_0 && dwRet <= (WAIT_OBJECT_0 + m_dwCount - 1)) {
				RemoveThread(dwRet - WAIT_OBJECT_0);
			}
			else if (dwRet == (WAIT_OBJECT_0 + m_dwCount)) {
				::GetMessage(&msg, NULL, 0, 0);

				// Another window is to be added - runs in a separate thread
				switch (msg.message) {
				case WM_USER:
					AddMainFrameThread(_T(""), SW_SHOWNORMAL);
					break;
				case WM_USER_WORKERTHREAD:
					AddWorkerThread(reinterpret_cast<void*>(msg.lParam));
					break;
				default:
					// Unexpected windows message got here!
					::MessageBeep((UINT)-1);
					break;
				}
			}
			else {
				::MessageBeep((UINT)-1);
			}
		}

		return nRet;
	}
};

/// \brief Get an allocated buffer with the fully qualified name of a module
///  Get the fully qualified name of a module, but ensure that
///  that it's in a dynamically allocated buffer of sufficient
///  size. I see no real alterantive to the cut and try method
///  below. Aargh.
/// \param hModule The module handle or NULL for the current program
/// \return An allocated buffer that needs to be free()'d. It may be NULL on error.
std::auto_ptr<char> MyGetModuleFileNameA(HMODULE hModule = NULL) {
	size_t cbFileName = 0;
	std::auto_ptr<char> szFileName;
	size_t cbLen;
	do {
		szFileName.reset(new char[cbFileName += MAX_PATH]);
		if (!szFileName.get()) {
			return std::auto_ptr<char>(NULL);
		}
		cbLen = GetModuleFileNameA(hModule, szFileName.get(), (DWORD)cbFileName);
		if (!cbLen) {
			return std::auto_ptr<char>(NULL);
		}
	} while (cbLen >= (cbFileName - 1));
	return szFileName;
}

int
WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR lpstrCmdLine, int nCmdShow) {
#ifdef _DEBUG
	// Set debug-flags
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF);
	//_CrtSetBreakAlloc(123);
#endif

	// Initialize global strings
	g_sAxCryptExtension = AxLib::CGettext::GetStringResource(IDS_AXX);

	// Set the language
	_putenv("LANGUAGE=se");

	std::auto_ptr<char> sLocaleDir(MyGetModuleFileNameA(NULL));
	ASSPTR(sLocaleDir.get());
	(void)PathRemoveFileSpecA(sLocaleDir.get());

	// Initialize gettext.
	AxLib::CGettext::BindTextDomain(GETTEXT_PACKAGE, sLocaleDir.get());
	AxLib::CGettext::TextDomain(GETTEXT_PACKAGE);
	AxLib::CGettext::BindTextDomainCodeset(GETTEXT_PACKAGE, "UTF-8");

	ASSCOM(::CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));

	AtlInitCommonControls(ICC_COOL_CLASSES | ICC_BAR_CLASSES | ICC_USEREX_CLASSES);

	ASSCOM(_Module.Init(NULL, hInstance));

	CThreadManager mgr;
	int nRet = mgr.Run(lpstrCmdLine, nCmdShow);

	_Module.Term();
	::CoUninitialize();

	return nRet;
}