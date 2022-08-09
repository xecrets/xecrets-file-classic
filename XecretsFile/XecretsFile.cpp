/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2002-2022 Svante Seleborg/Axon Data, All rights reserved.

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
	XecretsFile.cpp                 WinMain() and friends.

	E-mail                          YYYY-MM-DD              Reason
	software@axantum.com             2001                    Initial
	"								2001-11-19				SHChangeNotify on install/uninstall
	"								2001-11-29				Create new process instead of thread on
															first instance. Added some CAssertions.
															Changed from .App to .Sys in some cases.
															Fix for apps that don't start new
															processes. WaitForClose() et al.
	"								2001-12-15				Beta 5 - Heap and KeyStore as statics,
															not pointers, to help with construction etc.
									2002-08-06              Rel 1.2

*/
/*
	Compatibility:  Win 95/98/ME/NT/2K/XP.
					Attempts have been made to make a CE-port feasible - but not trivial.
					There is also an attempt to make it Unicode portable - untested...
					There is no hope of porting from the Windows platform. Sorry,
					that will require a partial re-write. It would be cool with a Mac-version and
					a Unix/Linux-version... Any takers ;-) ?

	A design goal has been to make it useful for low-bandwidth direct access
	situation such as intranets and web-based project repositories, therefore
	files are always compressed before encryption.

	Another design goal has been to use Windows API-code as much as possible,
	except for the actual crypto parts, since I want to make that part visible
	for full peer-review. Usage of Windows API's is somewhat limited by the idea
	of Win95 compatibility, especially some useful shell API's...

	Security Design Goals:

		-   A Key Encrypting Key can be broken only by brute force passphrase search.
		-   A Data Encrypting Key can be broken only by exhaustive search in the full key space.
		-   The local system key management is secure, provided that the system is not crashed at a point
			where the memory mapped heap-file actually resides on disk.
		-   Data is kept locally secure, excepting untimely crashes, with the caveat that we have no control
			of other applications caretaking of the data, i.e. temp-files and paging-files from Word etc.

	The extension .xxx is registered to start Xecrets File which
	then does the following:

	- Tries cached keys or asks if necessary for a key
	- Finds the original file name in the wrapped file
	- Decrypts
	- Expands to the original file name
	- Restores original file-times
	- Shells out to start the appropriate application
	- Waits for the started app to terminate.
	- Saves and checks file-times for update, if newer:
	- Compress
	- Encrypts using the same key to the original file name
	- Exits

	We are also hooked into the right-click properties menu of the shell
	with the action "Encrypt and Wrap with Xecrets File", as well as "Decrypt and Unwrap from Xecrets File".

	Internally there is one primary instance that responds to requests from
	subsequent instances. This is primarily to give central protected access to cached
	keys. This should probably be done through a COM-interface in the future...

	Each initiated action in the master instance creates a separate thread.
	There is no visible window - but one is created, among other things to listen and respond
	to termination requests such as log-off or shutdown. When asked to terminate, we will first
	wait for all threads to terminate before exiting ourselves.

	Since Named Pipes are not supported on Win95 we use a file-mapping view to
	communicate between master instance and requests. A mutex object is used to serialize the
	the use of the shared memory. When a request for encryption or decryption is to be sent,
	the process gets the mutex, writes a Request Struct to the file, sends a signal, waits for signal
	and finally releases the mutex when the master instance has copied the request and initiated a
	new thread.

	We keep track of all new threads in a simple manner, mostly to ensure that if the master instance
	is asked to exit, we can wait for all threads to finish first. We also use it to keep track of
	the key-data used for each thread.

	The code below and in associated files tend to be executed in different contexts, so
	some clarification may help... This executable may be the first instance, or it may
	not... We call that first instance the "primary", the rest "secondary".

	The code is presumably thread-safe, guarded with critical sections... I hope.

	A guide to my, sometimes inconsistent, dialect of hungarian may be in order...

	g - Global
	m_ - Class member
	s_ - Static (module local)
	h - Handle to something
	p - Pointer to something
	a - Array
	r - Reference to something
	b - Boolean (to be phased out and replaced with...)
	f - Also boolean...
	v - Void
	o - Octets (i.e. byte, unsigned char)
	e - Enum value/variable
	c - Constant (occasionally)
	cb - Count of Bytes
	cc - Count of Characters
	ut - User Type, i.e. Classes and Structs. Sometimes not used.
	T - Type - Denotes that a name is the name of a 'type'
	C - Class - Denotes that a name is the name of a class
	sz - Zero-byte terminated string - or wrapper class for strings.
	dw - Double Word, i.e. unsigned 32-bit
	qw - Quad Word, i.e. unsigned 64-bit
	dqw - Double Quad Word, i.e. unsigned 128-bit
	ui - unsigned int
	i - int (as prefix, i.e. relatively small value that may take negative values)
	i,j etc - As simple names - Loop counters
*/
#include    "StdAfx.h"
//
#include    "stdlib.h"
#include    "shlobj.h"
#include    "../XecretsFileCommon/CRegistry.h"
//
// This is to actually define the GUID in XecretsFileGUID.h.
//
#define     INITGUID
#include    <initguid.h>
#include    "../XecretsFileCommon/XecretsFileGUID.h"
//
#include    "CActiveThreads.h"
#include    "../AxWinLib/mygetopt.h"
#include    "CCryptoKey.h"
#include    "../XecretsFileCommon/CFileName.h"
#include    "FileCmd.h"
#include    "CChildProc.h"
#include    "CCryptoHeap.h"
#include    "../XecretsFileCommon/CVersion.h"
#include    "Dialog.h"
#include    "CEntropy.h"
#include    "CFileTemp.h"
#include    "../AxWinLib/GetModuleFileName.h"
#include "../AxWinLib/VistaOrLater.h"
#include    "../AxSigLib/CTrialMgr.h"
#include    <process.h>
#include    <shlwapi.h>
#include    <shellapi.h>
#include	<Accctrl.h>
#include	<Aclapi.h>
#include    <memory>

#include    <userenv.h>

#include    "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Crypt.cpp"

//
//  Interprocess times
//
#ifdef _DEBUG
#define MAX_WAIT_EVENT      INFINITE    // Time to wait for primary to ack an event signal
#define MAX_WAIT_PRIMARY    INFINITE    // Time to wait for primary to be ready
#define MAX_SLEEP_PRIMARY   500         // Time to sleep before trying again to get mutex
#define MAX_WAIT_WORKER     INFINITE    // Time to wait for a worker thread to finish.
#define MAX_WAIT_MAINWORKER INFINITE    // Time for exit, install etc.
#else
#define MAX_WAIT_EVENT      3000        // Time to wait for primary to ack an event signal
#define MAX_WAIT_PRIMARY    INFINITE    // Time to wait for primary to be ready
#define MAX_SLEEP_PRIMARY   500         // Time to sleep before trying again to
#define MAX_WAIT_WORKER     5000        // Time to wait for a worker thread to finish.
#define MAX_WAIT_MAINWORKER INFINITE    // Time for exit, install etc.
#endif
//
// Command Line Parameters
//
LPTSTR* tArgv;
int tArgc;

extern char** __argv;
extern int __argc;
//
// Type/Struct/Class declarations
//
struct SRequest {
	// In to primary
	enum eRequestType eRequest;
	TCHAR szParam1[MAX_PATH];       // First command parameter, if any.
	TCHAR szParam2[MAX_PATH];       // Second, ditto.
	TCHAR szIdTag[100];             // An id-tag, it must have some max-length...
	TCHAR szCurDir[MAX_PATH + 1];     // The requesters current directory
									// Space for extra backslash too...
	BOOL fIgnoreEncrypted;          // Ignore already encrypted files.
	BOOL fRecurseDir;               // Recurse into sub-directories
	DWORD CallerProcId;
	DWORD dwBatch;                  // The batch id of this request.
	DWORD nWipePasses;                // The number of passes to wipe.
	HWND hCurWnd;                   // The foreground window at the time of call
	HANDLE hStdOut;                 // Valid in the primary context.
	DWORD dwPrimaryThreadId;        // The primary command Thread Id so worker processes can post messages

	// Out from primary to secondary
	DWORD dwWorkerThreadId;
	DWORD dwWorkerUniqueInternalId;
	CProgressDialog* pDlgProgress;
	DWORD dwPrimaryProcessId;       // Primary process Id
	DWORD dwExitCode;
};
//
// Static variables
//
static int mfIsPrimary = false;
static axpl::ttstring msConfigErr;  ///< Keep the message for configuration error here.

static HANDLE ghMutex = NULL, ghSendEvent = NULL, ghReceiveEvent = NULL;
// Here we store a set of null security attributes to apply to the interprocess objects
// since the case may be that they are created impersonating an administrator during installation
// and then need to be used by an instance running as the original user.
static SECURITY_ATTRIBUTES* gpNullSecurityAttributes = NULL;

//static CProgressDialog dlgProgress;
//
// Used to ensure handling of new thread list
//
static CActiveThreads* gpCActiveThreadsRoot = NULL;
static CRITICAL_SECTION gThreadListCritical;
//
// Does not need critical section protection, as the mutex is used
// for synchronized access to this structure.
//
static SRequest* glpSRequest = NULL;// The command buffer structure (memory mapped file view)
//
//  Globals
//
HWND ghWnd;                         // The main window handle
HINSTANCE ghInstance;               // The main instance handle

//HWND ghProgressWnd;
//
//  Must be early, so as to be destructed late.
//
CHModule ghMsgModule = NULL;               // Need for messages

//
//  Define the secure heap unless running with C++ debug heap
//
#ifndef _DEBUGHEAP
static BOOL gfHeapValid = FALSE;
CPtrTo<CCryptoHeap> pgHeap;
#endif  _DEBUGHEAP
//
//  Define the global key store root - our holiest of holies...
//
//  These must come after gHeap declaration, as they must constructed
//  in the order heap, then keystore and destructed in the reverse order.
//  C++ specifies that they are constructed in the order of declaration,
//  and destructed in the reverse order, ergo...
//
CPtrTo<CKeyList> pgKeyList;             // Our own "in-memory" key store.

CPtrTo<CEntropy> pgEntropyPool;

CPtrTo<CCryptoRand> pgPRNG;

// It's a bit of a mess all these global pointers, but since we destroy them manually in
// DestroyGlobalsX with an atexit() function we have full control of these pointers, so it's
// really a waste have them use smart pointers of various kinds, either home-grown CPtrTo like
// the others, or std::auto_ptr.

// The global configuration tracker, loaded at run-time startup - ready to use!
CConfigVerify* gpConfig(NULL);

// The global trial counter tracker
CTrialMgr* gpTrialMgr(NULL);

// The global license manager
CLicMgr* gpLicMgr(NULL);

// The global restriction manager
CRestrictMgr* gpRestrictMgr(NULL);

//
#ifndef _DEBUGHEAP
//
//  We override the new and delete operators to ensure that all allocs are 'secure'.
//
//  Special care is taken to handle the case of allocations/deletions when the heap
//  is not valid.
//
//  #define _DEBUGHEAP to use C++ standard heap instead - good for debugging!
//
#ifdef  _DEBUG
__declspec(thread) size_t tguiAlloc = 0;
static size_t cbDbgAllocs = 0;
#endif

void*
basenew(size_t stOctets) {
	if (gfHeapValid && pgHeap->heap != NULL) {
#ifdef  _DEBUG
		// Add size of the overhead block, and align to even multiple of such block.
		size_t size = stOctets + sizeof UNIT + sizeof UNIT - 1;
		tguiAlloc += size & ~(sizeof UNIT - 1);
		if (stOctets > 16 && stOctets <= 20) {
			cbDbgAllocs++;
		}
#endif

		return pgHeap->Alloc(stOctets);
	}
	else {
		return malloc(stOctets);
	}
}

void* operator new(size_t stOctets) {
	return basenew(stOctets);
}

/// \brief Array new, minimal implementation (same as new).
///
/// new/new[]/delete/delete[] are all compatible in this mini-implementation
/// \param cb The number of bytes
/// \return A pointer to the memory block, or NULL
void* operator new[](size_t cb) {
	return basenew(cb);
}

#pragma warning( disable : 4311 4312 )
void operator delete(void* vpMem) {
	if (!gfHeapValid ||
		pgHeap->heap == NULL ||
		vpMem < pgHeap->heap ||
		vpMem >= (void*)((char*)pgHeap->heap + pgHeap->m_stHeapLen)) {
		free(vpMem);
	}
	else {
#ifdef  _DEBUG
		UNIT* p = (UNIT*)((size_t)vpMem - sizeof UNIT);
		if ((p->size & ~USED) == 24) {
			cbDbgAllocs--;
		}
		tguiAlloc -= (p->size & ~USED);
#endif

		pgHeap->Free(vpMem);
	}
}
#pragma warning( default : 4311 4312 )

/// \brief free a previously allocated memory block
///
/// new/new[]/delete/delete[] are all compatible in this mini-implementation
/// \param p Pointer to a memory block, or NULL (ignored)
void operator delete[](void* p) {
	delete p;
}

#endif  _DEBUGHEAP
//
//  When launching apps, we need to be alone for a while so we can find exactly the right
//  child process.
//
CRITICAL_SECTION gLaunchAppCritical;
//
//  The current directory is not thread-safe, and although we do not want to modify it,
//  certain windows shell routines do anyway it seems...
//
CRITICAL_SECTION gCurrentDirectoryCritical;
//
//  Walk and clean the list of active threads, if possible.
//  Use timeout as given in the argument. No guarantee of
//  empty list - check after call.
//
static void
PurgeThreadList(DWORD dwTimeOut) {
	CCriticalSection utThreadListCritical(&gThreadListCritical);

	utThreadListCritical.Enter();       // Destructor will ensure we leave the critical section
	CActiveThreads* pActiveThread = gpCActiveThreadsRoot;
	while (pActiveThread != NULL) {
		HANDLE hThread = pActiveThread->Thread();
		utThreadListCritical.Leave();

		// Wait for the thread to finish or whatever.
		DWORD dwReturn = MessageWaitForSingleObject(hThread, dwTimeOut);

		// If it is abandoned, remove it and reset the search pointer to the root.
		if (dwReturn == WAIT_OBJECT_0) {
			// This critical section stuff should really be done by CActiveThreads...
			utThreadListCritical.Enter();
			gpCActiveThreadsRoot->Remove(gpCActiveThreadsRoot, pActiveThread->UniqueInternalId());
			pActiveThread = gpCActiveThreadsRoot;
		}
		else {
			utThreadListCritical.Enter();
			pActiveThread = pActiveThread->Next();
		}
	}
	utThreadListCritical.Leave();
}

static void
TrimProcess() {
	// Normally Windows will trim memory when a window is minimized, but there appears to be no easy way
	// to achieve this with a hidden window, so we'll just ask it here instead. This is really just for show,
	// lot's of users monitor process memory usage in Windows Task Manager, and think that just because it says
	// xMb there, that's memory wasted that could be used for something else. This is not how Windows virtual memory
	// works, but it's easier to trim memory here to make it look nicer than try to educate people about this. The
	// truth is that there's a risk of a slight performance penalty instead.

	// Since we can't be sure that the SetProcessWorkingSetSize API exists, we load this dynamically here.
	typedef BOOL(WINAPI* pfSetProcessWorkingSetSizeT)(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize, SIZE_T dwMaximumWorkingSetSize);

	// To avoid a lookup every time we keep it here, static
	static pfSetProcessWorkingSetSizeT pfSetProcessWorkingSetSize = reinterpret_cast<pfSetProcessWorkingSetSizeT>(~NULL);

	// If we've alread attempted to load the API, it'll be either NULL or the real address. If it's first time, it'll be ~NULL
#pragma warning(push)
#pragma warning(disable:4191)
	if (pfSetProcessWorkingSetSize == reinterpret_cast<pfSetProcessWorkingSetSizeT>(~NULL)) {
		pfSetProcessWorkingSetSize = reinterpret_cast<pfSetProcessWorkingSetSizeT>(GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "SetProcessWorkingSetSize"));
	}
#pragma warning(pop)
	if (pfSetProcessWorkingSetSize != NULL) {
		// Since this is all for show, we ignore the result here, but store it for debugging etc
		BOOL bResult = pfSetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
	}
}

//
//  Clean up, ensure that threads are closed etc. It risks being called
//  twice, but should only attempt to do any work the first time.
//
//  When this function is called, the decision to exit must be final, and
//  memory allocations/deletions should not be called unless you know what
//  you are doing. We also close the mutex, so we really, really, should
//  exit when this is called.
//
//  exit() should be called immediately after calling this function.
//
static void
PrimaryPrepareForExit() {
	static int fBeenHereOnce = FALSE;
	if (!fBeenHereOnce) {
		fBeenHereOnce = TRUE;

		pgEntropyPool->Stop();
		PurgeThreadList(1000);          // Give each thread 1 second
		(void)CloseHandle(ghMutex);
		ghMutex = NULL;
	}
}
//
// The main instance windows message process procedure
//
// "Primary Window Proc Main Thread"
//
static LRESULT CALLBACK
PrimaryWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CREATE:
		// Initialize the window.
		break;

	case WM_PAINT:
		// Paint the window's client area - actually do nothing to it.
		RECT stRect;
		if (GetUpdateRect(hWnd, &stRect, FALSE)) {
			PAINTSTRUCT stPaint;
			HDC hHDC = BeginPaint(hWnd, &stPaint);
			(void)EndPaint(hWnd, &stPaint);
		}
		break;

		// Obsolete - but we support for older NT
	case WM_POWER:
		switch (wParam) {
		case PWR_SUSPENDREQUEST:
			CMessage().Wrap(0).AppMsg(INF_DEBUG, _T("PWR_SUSPENDREQUEST")).LogEvent(2);
			pgEntropyPool->Stop().Save();
			return PWR_OK;

		case PWR_CRITICALRESUME:
		case PWR_SUSPENDRESUME:
			pgEntropyPool->Start();
			return 0;
		}
		break;  // dummy...

	case WM_POWERBROADCAST:
		switch (wParam) {
		case PBT_APMSUSPEND:
			CMessage().Wrap(0).AppMsg(INF_DEBUG, _T("PBT_APMSUSPEND")).LogEvent(2);
			pgEntropyPool->Stop().Save();
			return 0;

			// Currently, always allow. In the future - check for ongoing transforms and
			// possible other cases that may conflict.
		case PBT_APMQUERYSUSPEND:
			return TRUE;

			// As we did not do anything during query suspend - we do not need to undo
			// anything here.
		case PBT_APMQUERYSUSPENDFAILED:
			return 0;

		case PBT_APMRESUMEAUTOMATIC:
		case PBT_APMRESUMECRITICAL:
		case PBT_APMRESUMESUSPEND:
			pgEntropyPool->Start();
			return 0;
		}
		return 0;   // Dummy

	case WM_QUERYENDSESSION:
		// If there are no active apps, there is no problem, we always
		// allow shutdown.
		//
		// If there are active apps, we ask if we should allow system shutdown,
		// as in this case the user can switch to the other apps and terminate
		// them before killing the dialog.
		//
		PurgeThreadList(0);     // Clean out any abandoned threads
		if (gpCActiveThreadsRoot == NULL) return TRUE;

		return CMessage().AppMsg(WRN_ACTIVE_APPS).ShowDialog(MB_OKCANCEL | MB_ICONWARNING) == IDOK;
		break;

	case WM_ENDSESSION:
		//
		// If WM_QUERYSESION allowed us to exit, wait for children to exit before...
		// It should be noted that when we get here, we cannot stop the shutdown, we
		// can only delay it.
		//
		if ((BOOL)wParam) {
			// We need to warn about active other programs.
			PurgeThreadList(0);     // Clean out any abandoned threads
			while (gpCActiveThreadsRoot != NULL) {
				CMessage().AppMsg(WRN_SHUT_DOWN).ShowWarning(MB_OK);
				PurgeThreadList(0);     // Clean out any abandoned threads
			}
			PrimaryPrepareForExit();
			pgEntropyPool->Save();  // Always save entropy when asked to exit by system.
			// ...really terminating under our own control, ensuring clean-up
			exit(0);
		}
		// ... else just return 0 to say we was here
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;

	default:
		return DefWindowProc(hWnd, uMsg, wParam, lParam);
	}
	return 0;
}
//
// Register the Window Class
//
// "Primary Window Proc Main Thread"
//
static BOOL
PrimaryInitApplication(HINSTANCE hInstance) {
	WNDCLASSEX wcx;

	ZeroMemory(&wcx, sizeof wcx);
	wcx.cbSize = sizeof wcx;            // size of structure
	wcx.style = CS_HREDRAW |
		CS_VREDRAW;                     // redraw if size changes
	wcx.lpfnWndProc = PrimaryWndProc;       // points to window procedure
	wcx.cbClsExtra = 0;                 // no extra class memory
	wcx.cbWndExtra = 0;                 // no extra window memory
	wcx.hInstance = hInstance;          // handle of instance
	wcx.hIcon = (HICON)LoadImage(
		hInstance,
		MAKEINTRESOURCE(IDI_XECRETSFILE),
		IMAGE_ICON,
		GetSystemMetrics(SM_CXICON),
		GetSystemMetrics(SM_CYICON),
		LR_DEFAULTCOLOR);               // Application Icon
	CAssert(wcx.hIcon != NULL).Sys().Throw();
	wcx.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcx.hbrBackground = (HBRUSH)GetStockObject(
		WHITE_BRUSH);                   // white background brush
	wcx.lpszClassName = gszAxCryptInternalName; // name of window class
	wcx.hIconSm = (HICON)LoadImage(hInstance,
		MAKEINTRESOURCE(IDI_XECRETSFILE),
		IMAGE_ICON,
		GetSystemMetrics(SM_CXSMICON),
		GetSystemMetrics(SM_CYSMICON),
		LR_DEFAULTCOLOR);               // Small class icon
	CAssert(wcx.hIconSm != NULL).Sys().Throw();

	return RegisterClassEx(&wcx) != 0;
}
//
// Create a window to receive messages etc
//
// "Primary Window Proc Main Thread"
//
static BOOL
PrimaryInitInstance(HINSTANCE hInstance, int nCmdShow, HWND* phWnd) {
	CVersion utVersion;
	*phWnd = CreateWindow(
		gszAxCryptInternalName,// name of window class
		utVersion.String(gfAxCryptShowNoVersion),     // title-bar string
		WS_TILEDWINDOW | WS_MINIMIZE,
		0, // Zero Size
		0,
		0,  // Zero Position
		0,
		(HWND)NULL,             // no owner window
		(HMENU)NULL,            // use class menu
		hInstance,              // handle of application instance
		(LPVOID)NULL);         // no window-creation data

	if (*phWnd == NULL) {
		return FALSE;
	}

	// Show the window and send a WM_PAINT message to the window
	// procedure. Hide it if we are in production.
#if     defined(_DEBUG)
	ShowWindow(*phWnd, nCmdShow);
#else
	ShowWindow(*phWnd, SW_HIDE);
#endif
	UpdateWindow(*phWnd);
	TrimProcess();
	return TRUE;
}

struct FindProgressWndS {
	DWORD dwProcID;         // In
	HWND hProgressWnd;      // Out
};

static BOOL CALLBACK
EnumProgressProc(HWND hWnd, LPARAM lParam) {
	struct FindProgressWndS* pFindProgressWnd = (struct FindProgressWndS*)lParam;
	if (GetClassLongPtr(hWnd, GCW_ATOM) == (ULONG_PTR)WC_DIALOG) {
		// We used to specify a window name here to further narrow it down, but in Vista you can't set a window name
		// on a progress window it appears. Since we anyway ascertain that it's the right progress window by checking
		// the user data against the expected process ID it feels good enough.
		HWND hProgressWnd = FindWindowEx(hWnd, NULL, PROGRESS_CLASS, NULL);
		if (hProgressWnd != NULL) {
			if ((DWORD)GetWindowLongPtr(hProgressWnd, GWLP_USERDATA) == pFindProgressWnd->dwProcID) {
				pFindProgressWnd->hProgressWnd = hProgressWnd;
				return FALSE;
			}
		}
	}
	return TRUE;    // Continue looking
}
//
//  Find a PROGRESS_CLASS window, that is a child window of a
//  top-level dialogue, with GWL_USERDATA == dwProcID.
//
static HWND
FindProgressWnd(DWORD dwProcID) {
	struct FindProgressWndS sFindProgressWnd;
	sFindProgressWnd.dwProcID = dwProcID;
	sFindProgressWnd.hProgressWnd = NULL;
	EnumWindows(EnumProgressProc, (LPARAM)&sFindProgressWnd);
	return sFindProgressWnd.hProgressWnd;
}
DWORD
DoCmdFileExpand(pfCmdT pfCmd, CCmdParam* pCmdParam) {
	CFileName fn;
	if (PathIsRelative(pCmdParam->szParam1.c_str())) {
		TCHAR path[MAX_PATH];

		PathCombine(path, pCmdParam->szCurDir.c_str(), pCmdParam->szParam1.c_str());
		fn.Set(path);
	}
	else {
		fn.Set(pCmdParam->szParam1.c_str());
	}

	axpl::ttstring szDir = fn.GetDir();
	axpl::ttstring szTitle = fn.GetTitle();

	// Simple check for wild-cards
	if (_tcschr(szTitle.c_str(), _T('*')) || _tcschr(szTitle.c_str(), _T('?'))) {
		CCmdParam cmdParam = *pCmdParam;

		return FileExpand(pfCmd, &cmdParam, szDir.c_str(), szTitle.c_str());
	}
	else {
		// If no wild-cards, just go easy and do as a single file-spec, but start
		// by filling in the full path
		pCmdParam->szParam1 = _tcsdup(fn.Get());
		DWORD dwReturn = (*pfCmd)(pCmdParam);
		return dwReturn;
	}
}

//
//  Prepare for ending the primary process.
//
static DWORD CmdExit(DWORD dwPrimaryThreadId) {
	// First let's give active threads up to a second to finish.
	for (int i = 0; i < 20; i++) {
		if (gpCActiveThreadsRoot == NULL) break;
		PurgeThreadList(0);
		Sleep(50);  // Wait just a little for potentially active threads.
	}
	// While we have any potentially active threads,
	// let's warn the user about this, and ...
	while (gpCActiveThreadsRoot) {
		//                          FlashBox();
		if (CMessage().AppMsg(WRN_ACTIVE_APPS).ShowWarning(MB_OKCANCEL) == IDCANCEL) {
			break;
		}
	}
	DWORD dwExitCode = gpCActiveThreadsRoot ? ERR_UNSPECIFIED : 0;
	PostThreadMessage(dwPrimaryThreadId, WM_QUIT, dwExitCode, 0);

	return dwExitCode;
}

//
// This is where we do the actual work. As we want the message loop to continue
// we create a separate thread for it.
//
// The request buffer is allocated by the caller, and must be deallocated here
//
// "Primary Execute Request Thread", This is the actual worker thread.
//
static DWORD WINAPI
PrimaryCommandThreadInternal(LPVOID lpParam) {
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	struct SRequest* lpSRequest = (SRequest*)lpParam;
	DWORD dwReturn = 0;

	// We used to need this, just keeping it as a neat trick
	// so I won't forget it... ;-)
	//
	// Force the creation of a message queue in this thread. This
	// is necessary for MessageBox() dialogs etc, even if we don't
	// actually have a message loop!
	//MSG msg;
	//PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

	CCmdParam utCmdParam;
	try {
		ZeroMemory(&utCmdParam, sizeof utCmdParam);

		if (lpSRequest->szParam1[0]) utCmdParam.szParam1 = lpSRequest->szParam1;
		if (lpSRequest->szParam2[0]) utCmdParam.szParam2 = lpSRequest->szParam2;
		if (lpSRequest->szIdTag[0]) utCmdParam.szIdTag = lpSRequest->szIdTag;

		// Pass the current directory as well.
		utCmdParam.szCurDir = lpSRequest->szCurDir;

		utCmdParam.dwBatch = lpSRequest->dwBatch;
		utCmdParam.nWipePasses = lpSRequest->nWipePasses;
		utCmdParam.fIgnoreEncrypted = lpSRequest->fIgnoreEncrypted;
		utCmdParam.fRecurseDir = lpSRequest->fRecurseDir;
		utCmdParam.hForegroundWnd = lpSRequest->hCurWnd;
		utCmdParam.pDlgProgress = lpSRequest->pDlgProgress;
		utCmdParam.hProgressWnd = FindProgressWnd(lpSRequest->CallerProcId);
		utCmdParam.hStdOut = lpSRequest->hStdOut;

		HEAP_CHECK_BEGIN(_T("PrimaryCommandThread()"), 0)
			switch (lpSRequest->eRequest) {
			case EN_WIPE:   // Wipe
				dwReturn = DoCmdFileExpand(CmdWipe, &utCmdParam);
				break;
			case EN_WIPES:  // Wipe silen
				dwReturn = DoCmdFileExpand(CmdWipeSilent, &utCmdParam);
				break;
			case EN_OPEN:   // Launch and open, possibly re-encrypting
				utCmdParam.fSlowSafe = TRUE;
				// For the open command - we always use our own progress window
				if (lpSRequest->pDlgProgress) {
					if (utCmdParam.hProgressWnd = lpSRequest->pDlgProgress->Wnd()) {
						// Set the file name in the progress window as well...
						SetDlgItemText(GetParent(utCmdParam.hProgressWnd), IDS_FILE, utCmdParam.szParam1.c_str());
					}
				}
				dwReturn = CmdDecryptOpenLaunch(&utCmdParam);
				break;
			case EN_ENCRYPTZC: // Encrypt and Copy
				utCmdParam.fSlowSafe = TRUE;
				dwReturn = DoCmdFileExpand(CmdEncryptZCFile, &utCmdParam);
				break;
			case EN_SFXENCNEW: // Encrypt and copy to new SFX
				utCmdParam.fSlowSafe = TRUE;
				dwReturn = DoCmdFileExpand(CmdSfxEncNewFile, &utCmdParam);
				break;
			case EN_ENCRYPTZCF: // Encrypt and Copy, Fast(er)
				// When in the 'fast' mode, we do not wipe temps.
				utCmdParam.fSlowSafe = FALSE;
				dwReturn = DoCmdFileExpand(CmdEncryptZCFile, &utCmdParam);
				break;
			case EN_ENCRYPTZ:   // Encrypt and wipe originals
				utCmdParam.fSlowSafe = TRUE;
				dwReturn = DoCmdFileExpand(CmdEncryptZFile, &utCmdParam);
				break;
			case EN_DECRYPT:    // Decrypt and wipe originals.
				utCmdParam.fSlowSafe = TRUE;
				dwReturn = DoCmdFileExpand(CmdDecryptFile, &utCmdParam);
				break;
			case EN_ENCRYPTZF:   // Encrypt and wipe originals
				utCmdParam.fSlowSafe = FALSE;
				dwReturn = DoCmdFileExpand(CmdEncryptZFile, &utCmdParam);
				break;
			case EN_DECRYPTF:    // Decrypt and wipe originals.
				utCmdParam.fSlowSafe = FALSE;
				dwReturn = DoCmdFileExpand(CmdDecryptFile, &utCmdParam);
				break;
			case EN_DECRYPTC:   // Decrypt and copy
				utCmdParam.fSlowSafe = TRUE;
				dwReturn = DoCmdFileExpand(CmdDecryptCFile, &utCmdParam);
				break;
			case EN_DECRYPTCF:  // Decrypt and copy, fast(er)
				utCmdParam.fSlowSafe = FALSE;
				dwReturn = DoCmdFileExpand(CmdDecryptCFile, &utCmdParam);
				break;
			case EN_ADDKEYENC:  // Add a default encryption key to the cache
				utCmdParam.fIsEncKey = TRUE;
				dwReturn = CmdAddKey(&utCmdParam);
				break;
			case EN_MAKEKEYFILE: // Create and save a key file
				dwReturn = CmdMakeKeyFile(&utCmdParam);
				break;
			case EN_ADDKEYDEC:  // Add a decryption key to the cache
				utCmdParam.fIsEncKey = FALSE;
				dwReturn = CmdAddKey(&utCmdParam);
				break;
			case EN_ASKKEYENC:  // Ask for a (default) encryption key
				utCmdParam.fIsEncKey = TRUE;
				dwReturn = CmdPromptKey(&utCmdParam);
				break;
			case EN_ASKKEYDEC:  // Ask for a decryption key
				utCmdParam.fIsEncKey = FALSE;
				dwReturn = CmdPromptKey(&utCmdParam);
				break;
			case EN_CLEARKEYS:  // Clear all keys in cache, depending on batch id
				dwReturn = CmdClearKeys(&utCmdParam);
				break;
			case EN_RENAME:     // Rename to anonymous name.
				dwReturn = DoCmdFileExpand(CmdAnonRename, &utCmdParam);
				break;
			case EN_BRUTEFORCE:
				dwReturn = CmdBruteForce(&utCmdParam);
				break;
			case EN_SHOWTAG:    // Display the tag
				dwReturn = DoCmdFileExpand(CmdShowIdTag, &utCmdParam);
				break;
			case EN_INSTALL:    // Install default settings in registry
				dwReturn = CmdInstallInRegistry(&utCmdParam);     // Just setup registry etc.
				SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT, 0, 0);
				break;
			case EN_UNINSTALL:  // Clear all registry entries
				dwReturn = CmdRemoveFromRegistry(&utCmdParam);  // Remove all settings from registry etc.
				SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT, 0, 0);
				break;
			case EN_PSPTEST:
				dwReturn = CChildProc().NeedPsapi() ? 1 : 0;
				break;
			case EN_TESTHAVEKEY:    // Test if we have the key. Zero if we do...
				dwReturn = DoCmdFileExpand(CmdTestHaveKey, &utCmdParam);
				break;
			case EN_LICENSEMGR:
				dwReturn = CmdLicenseMgr(&utCmdParam);
				break;
			case EN_REGISTRATION:
				dwReturn = CmdRegistration(&utCmdParam);
				break;
			case EN_EXIT:
				dwReturn = CmdExit(lpSRequest->dwPrimaryThreadId);
				break;
			default:
				dwReturn = ERR_UNSPECIFIED;
				break;
			}
		HEAP_CHECK_END
			// Close handle to caller std out, if we have it.
			if (lpSRequest->hStdOut != NULL && lpSRequest->hStdOut != INVALID_HANDLE_VALUE) {
				CAssert(CloseHandle(lpSRequest->hStdOut)).Sys().Throw();
			}
	}
	catch (TAssert utErr) {
		OutputDebugString(L"Caught unhandled C++ exception in PrimaryCommandThreadInternal");
		utErr.App(ERR_UNTRAPPED).Show();
		dwReturn = ERR_UNTRAPPED;
	}

	// Allocated by caller, must be released here
	if (lpSRequest->pDlgProgress) {
		delete lpSRequest->pDlgProgress;
		lpSRequest->pDlgProgress = NULL;
	}
	delete lpSRequest;
	lpSRequest = NULL;

	//#ifdef XXXYYY
		// In server-mode, we cause a special shell-out if the problem
		// was that a passphrase was needed!
	if (dwReturn == ERR_NO_PASSPHRASE) {
		CPtrTo<TCHAR> szCmdFmt = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerErrorShell).GetSz(_T(""));
		if (*szCmdFmt) {
			LPTSTR szCmd;
			CAssert(FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY,
				szCmdFmt,
				0,
				0,
				(LPTSTR)&szCmd,
				0,
				(va_list*)&utCmdParam.szParam1)).Sys(MSG_SYSTEM_CALL, _T("PrimaryCommandThread() [FormatMessage()]")).Throw();

			STARTUPINFO StartupInfo;
			ZeroMemory(&StartupInfo, sizeof StartupInfo);
			StartupInfo.cb = sizeof StartupInfo;

			PROCESS_INFORMATION ProcessInfo;
			if (CreateProcess(NULL,
				szCmd,
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				NULL,
				&StartupInfo,
				&ProcessInfo)) {
				CMessage().Wrap(0).AppMsg(INF_SERVER_SHELL, szCmd).LogEvent(1);
			}
			else {
				DWORD dwErr = GetLastError();
				CMessage().Wrap(0).AppMsg(ERR_SERVER_SHELL, szCmd, CMessage().SysMsg(dwErr).GetMsg()).LogEvent(0);
			}
			LocalFree(szCmd);
		}
	}
	//#endif
	CoUninitialize();

	TrimProcess();

	return dwReturn;
}

LONG MyFilter(PEXCEPTION_POINTERS pExceptionInfo) {
	static wchar_t s[1000];

	wsprintf(s, L"ExceptionCode=0x%08X", pExceptionInfo->ExceptionRecord->ExceptionCode);
	OutputDebugString(s);

	return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI
PrimaryCommandThread(LPVOID lpParam) {
	DWORD dwReturn = 1;
	__try {
		dwReturn = PrimaryCommandThreadInternal(lpParam);
	}
	__except (MyFilter(GetExceptionInformation())) {
	}
	return dwReturn;
}

void
ApplyTerm(const XNode* pTerms) {
	for (XAttrs::const_iterator it = pTerms->attrs.begin(); it != pTerms->attrs.end(); it++) {
		// If the license is valid, apply these restrictions - possibly clearing them.
		if (gpLicMgr->ChkType(pTerms->value)) {
			gpRestrictMgr->Set((*it)->name, (*it)->value);
			if (TTStringCompareIgnoreCase((*it)->name, _TT("uses")) && (*it)->value.empty()) {
				// Clean up the counter store. This should be done in a more efficient
				// way, but that'll have to be fixed later.
				gpTrialMgr->Clear();
			}
		}
	}
}
void
ApplyTerms(const XNode* pRestrictXML) {
	// Now iterate through the terms, and see if we should modify the initial restrictions
	for (XNodes::const_iterator it = pRestrictXML->childs.begin(); it != pRestrictXML->childs.end(); it++) {
		// If these are terms, to apply if the license is valid...
		if (TTStringCompareIgnoreCase((*it)->name, _TT("terms"))) {
			ApplyTerm(*it);
		}
	}
}

/// \brief Validate signatures and configuration XML etc
/// Sigs.xml must be present, and it must point to a valid and signed configuration file.
/// Here we prepare the global configuration object, gConfig for all further use.
/// On entry, we have already attempted to load the signature XML in the constructor.
static bool
ValidateSigsEtc() {
	// Find the path to the exectuable folder.
	auto_ptr<_TCHAR> szModulePath(MyGetModuleFileName(NULL));
	ASSPTR(szModulePath.get());
	_TCHAR* szModuleName = PathFindFileName(szModulePath.get());
	ASSAPI(PathRemoveFileSpec(szModulePath.get()));

	gpConfig = new CConfigVerify(szSigsXML, szModulePath.get());

	// Validate that we actually have some signature XML
	if (gpConfig->GetSigsXML() == NULL) {
		msConfigErr = gpConfig->GetLastErrorMsg();
		return false;
	}

	// Load our public key - this can't fail - if it does we assert in this function.
	gpConfig->SetBEREncodedFilePublicKey(bPublicRootKey, cbPublicRootKey);

	// Now check all signatures that are referenced in the Signature XML
	ttstringpairvector spvFileSigs;
	gpConfig->GetFilesSigsFromXML(gpConfig->GetSigsXML(), spvFileSigs);
	if (!gpConfig->VerifyFiles(spvFileSigs, szModulePath.get())) {
		msConfigErr = gpConfig->GetLastErrorMsg();
		return false;
	}

	// Since we now have checked all signatures in the Signature XML, if we have
	// any configuration XML - it is valid by inference.
	if (!gpConfig->LoadConfig(gpConfig->GetSigsXML(), szModulePath.get())) {
		msConfigErr = gpConfig->GetLastErrorMsg();
		return false;
	}

	// Now check all signatures in the configuration
	spvFileSigs.clear();
	gpConfig->GetFilesSigsFromXML(gpConfig->GetConfigXML(), spvFileSigs);
	if (!gpConfig->VerifyFiles(spvFileSigs, szModulePath.get())) {
		msConfigErr = gpConfig->GetLastErrorMsg();
		return false;
	}

	// Finally check that the configuration actually is for us - down to the name of
	// the executable. The same binary may be distributed under different names - here
	// we check this.
	if (!gpConfig->VerifyName(gpConfig->GetConfigXML(), szModuleName)) {
		msConfigErr = _TT("This configuration is not for me!");
		return false;
	}

	// Find the name of the restrictions as we want to refer to them
	const XNode* pRestrictXML = gpConfig->GetElementXML(gpConfig->GetConfigXML(), _TT("restrictions"));
	if (pRestrictXML) {
		const axpl::ttstring sRestrictName = pRestrictXML->value;
		// If we have an appropriate restritions section, we make a trial manager - otherwise not, it doesn't
		// make sense to have one if we're not going to use it.
		if (!sRestrictName.empty()) {
			gpTrialMgr = new CTrialMgr(sRestrictName);

			// If we have restrictions, let's get licenses and all that
			axpl::ttstring sLicenseVerifier = gpConfig->GetFromXML(pRestrictXML, _TT("verifier")).first;
			// If there's a verifier in the restrictions section...
			if (!sLicenseVerifier.empty()) {
				// ...load the public verifier for licenses for this program. This has to succeed, otherwise
				// the constructor asserts. The config is signed, so it really should be correct.
				gpLicMgr = new CLicMgr(sLicenseVerifier);

				// Now that we have a license verifier, we'll see which ones that are valid.
				// The licenses are found in the Sigs XML and in the registry
				// Start with the registry - this is always the "full" type
				CRegistry regKey(HKEY_CURRENT_USER, gszAxCryptRegKey);
				if (gpLicMgr->AddChkType(_TT("Full"), regKey.Value(szRegValLicensee).GetSz(_T("")), regKey.Value(szRegValSignature).GetSz(_T("")))) {
					// The signature was valid - then we want to show the activation status menu item.
					regKey.Value(szRegValShowActivationMenu).SetDword(TRUE);
				}
				else {
					// If no Current User "Full" license found, continue with Local Machine registry
					regKey.Root(HKEY_LOCAL_MACHINE).Key(gszAxCryptRegKey);
					if (gpLicMgr->AddChkType(_TT("Full"), regKey.Value(szRegValLicensee).GetSz(_T("")), regKey.Value(szRegValSignature).GetSz(_T("")))) {
						// The signature was valid - then we want to show the activation status menu item.
						regKey.Value(szRegValShowActivationMenu).SetDword(TRUE);
					}
					else {
						// If no Local machine "Full" license found, check the Sigs XML
						const XNode* pLicensesXML = gpConfig->GetElementXML(gpConfig->GetSigsXML(), _TT("licenses"));
						if (pLicensesXML) {
							for (XNodes::const_iterator it = pLicensesXML->childs.begin(); it != pLicensesXML->childs.end(); it++) {
								axpl::ttstring sType, sLicensee, sLicense;
								if (TTStringCompareIgnoreCase((*it)->name, _TT("signature"))) {
									for (XAttrs::const_iterator ait = (*it)->attrs.begin(); ait != (*it)->attrs.end(); ait++) {
										if (TTStringCompareIgnoreCase((*ait)->name, _TT("terms"))) {
											sType = (*ait)->value;
										}
										else if (TTStringCompareIgnoreCase((*ait)->name, _TT("licensee"))) {
											sLicensee = (*ait)->value;
										}
									}
									sLicense = (*it)->value;
									// Empty type is acceptable, it's the default
									if (!sLicense.empty() && !sLicensee.empty()) {
										// Add the new license type.
										if (gpLicMgr->AddChkType(sType, sLicensee, sLicense)) {
											// The license was valid
										}
									}
								}
							}
						}
					}
				}
				// Now we know which license are valid - let's interpret the restrictions in this
				// context. We go through the restrictions, one by one and apply them. The attributes
				// of the <Restrictions> element determine the default restrictions that apply, if any.
				// A valid <Terms> element determine what is modfied of the restrictions. We feed the
				// RestictionMgr with restrictions as we parse the XML. It's then up to the rest of the
				// code to use the restrictions if it pleases it.

				// Create the global restriction manager
				gpRestrictMgr = new CRestrictMgr;

				// Setup the initial restrictions
				for (XAttrs::const_iterator it = pRestrictXML->attrs.begin(); it != pRestrictXML->attrs.end(); it++) {
					gpRestrictMgr->Set((*it)->name, (*it)->value);
				}
				ApplyTerms(pRestrictXML);
			} // (otherwise if there is no restrictions section in the config we have permanent restrictions - if any)
		}
	}
	return true;
}

//
//  Do all primary-specific initialization
//
static void
PrimaryInit(int nCmdShow) {
	InitializeCriticalSection(&gThreadListCritical);
	InitializeCriticalSection(&gLaunchAppCritical);
	InitializeCriticalSection(&gCurrentDirectoryCritical);

	// Initialize application and instance
	CAssert(PrimaryInitApplication(ghInstance)).Sys(MSG_INIT_APPLICATION).Throw();
	CAssert(PrimaryInitInstance(ghInstance, nCmdShow, &ghWnd)).Sys(MSG_INIT_INSTANCE).Throw();

	// Initialize the global entropy pool
	pgEntropyPool = new CEntropy(HKEY_CURRENT_USER, gszAxCryptRegKey);
	ASSPTR(pgEntropyPool);

	// Start with cleaning temp directory, if needed.
	// Force focus from original window - otherwise me may lock-up the temp directory
	// if that is viewed in windows explorer.
	//MySetForegroundWindow();

	// Clean the old temp directory, if any. We need the entropy generator running,
	// as CTempDir needs random numbers.
	pgEntropyPool->Load().Start();
	{
		// Create and remove the temp-directory, if possible. The destructor will
		// clean up and warn if not possible
		CTempDir(CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValWipePasses).GetDword(1)).SetPath2TempDir();
	}

	pgEntropyPool->Stop().Save();

	// Create new tempdirectory and ensure that it is not compressed
	CFileIO utTmpDir;
	utTmpDir.OpenDir(CFileName().SetPath2TempDir().GetDir());
	utTmpDir.SetNotCompressed();
	utTmpDir.Close();

	// We do this before initializing the global heap, but we destroy the
	// objects before removing the global heap too. This is because std::streams
	// cause allocations that are not destructed until at C-runtime exit. If
	// these are done with the secure heap, they will crash the program because
	// the secure heap has gone by then. We can destruct objects on both heaps
	// when the are alive, but we cannot destruct heaps on the secure heap after
	// it has gone... This all needs cleaning up.
	(void)ValidateSigsEtc();                // Returns false on validation error, msConfigErr != ""

#ifndef _DEBUGHEAP
	// Then make the secure heap
	pgHeap = new CCryptoHeap(SECURE_HEAP_SIZE, &gfHeapValid);
	ASSPTR(pgHeap);

	pgHeap->Init();
#endif

	// ...and the global key store
	pgKeyList = new CKeyList;
	ASSPTR(pgKeyList);

	// ...and the PRNG
	pgPRNG = new CCryptoRand;
	ASSPTR(pgPRNG);

	pgEntropyPool->Load().Start();

	CMessage().Wrap(0).AppMsg(INF_APP_START).LogEvent();
	CAssert(ReleaseMutex(ghMutex)).Sys(MSG_SYSTEM_CALL, _T("ReleaseMutex() [StartPrimaryProcess()]")).Throw();

	// Set current directory to the user temp directory, to avoid locking a user directory
	CAssert(SetCurrentDirectory(CFileName().SetPath2SysTempDir().Get())).Sys(MSG_SYSTEM_CALL, _T("SetCurrentDirectory() [StartPrimaryProcess()]")).Throw();
}
//
//  Handle reception of primary process event request. Actually do some
//  work by spawning a worker thread for it.
//
static void
PrimaryEvent() {
	//
	//  At this point, we know we have received a request,
	//  the caller has the mutex, but has relinquished control
	//  of the shared memory to us through the event.
	//
	// Get a copy of the request code.
	enum eRequestType eRequest = glpSRequest->eRequest;

	// First we check if this is a request for our processid.
	// If so, we do that here, and then just return. We also allow that even if broken,
	// I think it's necessary for EN_EXIT and EN_UNINSTALL too - see below.
	if (eRequest == EN_GETPROCID) {
		glpSRequest->dwPrimaryProcessId = GetCurrentProcessId();
		CAssert(SetEvent(ghReceiveEvent)).Sys(MSG_SYSTEM_CALL, _T("SetEvent() EN_GETPROCID")).Throw();
		return;
	}

	// If we just want the exit code of a worker-thread, we don't want to start a new one for that...
	if (eRequest == EN_GETTHREADEXIT) {
		// We treat this also as a request to remove ourselves from the ActiveThread-list. It appears
		// that in Windows 2000, we can't open a thread by it's thread id after the thread has ended,
		// although this does seem to work in other os:s. The solution then is to use the handle we
		// already have in the active list, and keep that around until now. The drawback is that we'll
		// keep the handle to thread around until we get asked for the exit code (so all callers must),
		// since it's not really kosher to use the thread id as the key, because there's no guarantee
		// it won't get re-used the next millisecond. We use a unique internal id as key to avoid the risk
		// of collision.
		// The active list should be re-factored to use stl.

		// We are no longer active - lets leave! ActiveThread's destructor also
		// closes the thread handle stored there, but first let's also query for the exit code.
		CCriticalSection utThreadListCritical(&gThreadListCritical);
		utThreadListCritical.Enter();

		CActiveThreads* pActiveThread = gpCActiveThreadsRoot;
		glpSRequest->dwExitCode = MSG_INTERNAL_ERROR;
		while (pActiveThread != NULL) {
			if (pActiveThread->UniqueInternalId() == glpSRequest->dwWorkerUniqueInternalId) {
				if (!GetExitCodeThread(pActiveThread->Thread(), &glpSRequest->dwExitCode)) {
					glpSRequest->dwExitCode = GetLastError();
				}
				gpCActiveThreadsRoot->Remove(gpCActiveThreadsRoot, glpSRequest->dwWorkerUniqueInternalId);
				break;
			}
			pActiveThread = pActiveThread->Next();
		}
		utThreadListCritical.Leave();

		CAssert(SetEvent(ghReceiveEvent)).Sys(MSG_SYSTEM_CALL, _T("SetEvent() EN_GETTHREADEXIT")).Throw();
		return;
	}

	// For robustness we do allow EN_EXIT and some other operations even if we have corrupted
	// images, signalled by faulty signatures. EN_EXIT is needed during uninstall/upgrade
	// process, and uses the old verison, and it would be no good if you can't uninstall
	// if the program has become corrupted.
	if (!msConfigErr.empty()) {
		switch (eRequest) {
		case EN_EXIT:
		case EN_UNINSTALL:
		case EN_REGISTRATION:
		case EN_GETTHREADEXIT:
		case EN_LICENSEMGR:
		case EN_GETPROCID:
			// We allow this out of the goodness of our hearts... Even if you've corrupted me.
			// This might be the place to give the user a choice in the matter too.
			break;
		default:
			::MessageBox(NULL, msConfigErr.c_str(), CVersion().String(), MB_OK | MB_ICONWARNING);
			break;
		}
	}

	// Copy the command structure, start a new thread for the real action
	// and abandon it to it's own devices. Unless it's an exit event we
	// don't wait for it to finish.
	SRequest* lpSRequestCopy = new SRequest;
	ASSPTR(lpSRequestCopy);

	DWORD dwThreadID;
	// The copy is delete'd by the worker thread, so it must not
	// be used after we release the thread from suspension!
	CopyMemory(lpSRequestCopy, glpSRequest, sizeof SRequest);
	lpSRequestCopy->dwPrimaryThreadId = GetCurrentThreadId();

	// Deleted by the command thread.
	if (eRequest == EN_OPEN) {
		lpSRequestCopy->pDlgProgress = new CProgressDialog();
		ASSPTR(lpSRequestCopy->pDlgProgress);

		// There's a slight risk that the current window is actually another progress dialog, so we
		// traverse the list upwards before selecting the parent to ensure that no bad things happen
		// when we Destroy this window.
		HWND hParent = GetParent(glpSRequest->hCurWnd);
		if (hParent) {
			TCHAR szWinTxt[100];
			szWinTxt[0] = '\0';
			GetWindowText(hParent, szWinTxt, sizeof szWinTxt);
			if (_tcscmp(szWinTxt, CVersion(ghInstance).String(gfAxCryptShowNoVersion)) == 0) {
				hParent = glpSRequest->hCurWnd;
			}
		}
		else {
			hParent = glpSRequest->hCurWnd;
		}

		lpSRequestCopy->pDlgProgress->Create(ghInstance, IDD_PROGRESS, hParent, CVersion(ghInstance).String(gfAxCryptShowNoVersion));
	}
	else {
		lpSRequestCopy->pDlgProgress = NULL;
	}

	// Start the worker thread suspended so we can add it to the active
	// list first. It cannot be done in that thread, as the process may
	// terminate before it actually starts execution. Tried that ;-(.
	typedef unsigned(__stdcall* PTHREAD_START)(void*);
	HANDLE hWorkerThread;
	hWorkerThread = (HANDLE)_beginthreadex(NULL, 0, (PTHREAD_START)PrimaryCommandThread, lpSRequestCopy, CREATE_SUSPENDED, (unsigned*)&dwThreadID);
	CAssert(hWorkerThread != NULL).Sys(MSG_SYSTEM_CALL, _T("CreateThread()")).Throw();

	// Add the new thread to the active list.
	if (eRequest != EN_EXIT) {
		CCriticalSection utThreadListCritical(&gThreadListCritical);
		utThreadListCritical.Enter();
		CActiveThreads* pactiveThread = new CActiveThreads(gpCActiveThreadsRoot, hWorkerThread, dwThreadID);
		ASSPTR(pactiveThread);
		glpSRequest->dwWorkerUniqueInternalId = pactiveThread->UniqueInternalId();
		utThreadListCritical.Leave();
	}

	// Give the caller the thread id to wait for
	glpSRequest->dwWorkerThreadId = dwThreadID;

	// Don't let the worker thread affect foreground too much if it's a long operation
	CAssert(SetThreadPriority(hWorkerThread, THREAD_PRIORITY_BELOW_NORMAL)).Sys(MSG_SYSTEM_CALL, _T("PrimaryEvent() SetThreadPriority()")).Throw();

	// We can release the interprocess buffer, and let the caller get on with it.
	CAssert(SetEvent(ghReceiveEvent)).Sys(MSG_SYSTEM_CALL, _T("SetEvent()")).Throw();

	// There's no need to wait for anything more, we have acknowledged the caller and we're ready to run.

	// Make a copy of the handle for processing below, after we resume the
	// worker thread, we cannot use hWorkerThread, as it will be closed by the worker thread when it removes itself from the
	// active list.
	CHandle hWorkerThreadCopy;
	CAssert(DuplicateHandle(GetCurrentProcess(), hWorkerThread, GetCurrentProcess(), &hWorkerThreadCopy, 0, FALSE, DUPLICATE_SAME_ACCESS)).Sys(MSG_SYSTEM_CALL, _T("WinMain [DuplicateHandle -> hWorkerThreadCopy]")).Throw();

	// Now we can start the thread to actually run. lpSRequestCopy is subsequently invalid!!!
	CAssert(ResumeThread(hWorkerThread) != 0xffffffff).Sys(MSG_SYSTEM_CALL, _T("ResumeThread() [WinMain()]")).Throw();
	hWorkerThread = NULL; // Just to mark that it's no longer valid.

	// Save the pool
	// Event, Save the Pool on every event except the above
	pgEntropyPool->Save();

	// Close the work thread handle always.
	CAssert(hWorkerThreadCopy.Close()).Sys(MSG_SYSTEM_CALL, _T("WinMain [hWorkerThread.Close()]")).Throw();
}

//
//
//
void
DestroyGlobals1() {
	// Delete the PRNG..
	pgPRNG = NULL;

	// .. and delete the global key store...
	pgKeyList = NULL;

	// Just to confuse the issue, we're using a different strategy for the license stuff...
	// They are just pointers, not smart poiners. The reason being that the others should
	// be too - they are smart because of historical reasons, when the idea was to have them
	// cleaned up automatically at static object destruction time, but that didn't work out due
	// to complexities with the secure heap and the entropy pool, so that's why we have this
	// manual atexit() here - but the pointers never got changed back to regular ones... Not
	// this time either, I'm in a hurry.

	// The global restriction manager
	delete gpRestrictMgr;
	gpRestrictMgr = NULL;

	// The global license manager
	delete gpLicMgr;
	gpLicMgr = NULL;

	// The global trial counter tracker
	delete gpTrialMgr;
	gpTrialMgr = NULL;

	// The global configuration tracker, loaded at run-time startup - ready to use!
	delete gpConfig;
	gpConfig = NULL;

#ifndef _DEBUGHEAP
	// ... and and delete the secure heap...
	pgHeap = NULL;
#endif
}
//
//
//
void CleanTmp() {
	if (mfIsPrimary) {
		{
			// Create and remove the temp-directory, if possible. The destructor will
			// clean up and warn if not possible
			CTempDir(CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValWipePasses).GetDword(1)).SetPath2TempDir();
		}

		CMessage().Wrap(0).AppMsg(INF_APP_QUIT).LogEvent();
	}
}

void
DestroyGlobals2() {
	// .. and the entropy pool
	pgEntropyPool = NULL;
}

/*
static HHOOK hHook;
static HWND xxhWnd;
static LRESULT CALLBACK ShellProc(
  int nCode,      // hook code
  WPARAM wParam,  // event-specific information
  LPARAM lParam   // event-specific information
  ) {
	if (nCode < 0) {
		return CallNextHookEx(hHook, nCode, wParam, lParam);
	}
	xxhWnd = ((CWPSTRUCT *)lParam)->hwnd;
	return CallNextHookEx(hHook, nCode, wParam, lParam);
*/
/*
	switch (nCode) {
	case HCBT_ACTIVATE:
		xxhWnd = (HWND)wParam;
		break;
	case HCBT_CREATEWND:
		xxhWnd = (HWND)wParam;
		break;
	case HCBT_DESTROYWND:
		xxhWnd = (HWND)wParam;
		break;
	case HCBT_SETFOCUS:
		xxhWnd = (HWND)wParam;
		break;
//    case HSHELL_WINDOWREPLACED:
//        xxhWnd = (HWND)wParam;
		break;
	default:
		break;
	}
	return 0;
*/
/*
}
*/
//
//  Run the primary process - it's ok to try many times.
//  Only one is started though.
//
//  Try to create the Mutex, and get initial ownership
//
//  Return when we want to exit.
//
static int
PrimaryProcess(int nCmdShow) {
	// Create/Open the Mutex, and attempt to get initial ownership
	ghMutex = CreateMutex(gpNullSecurityAttributes, TRUE, gszAxCryptMutex);
	DWORD dwLastError = GetLastError();
	CAssert(ghMutex != NULL).App(MSG_CREATE_MUTEX, (LPTSTR)gszAxCryptMutex).Throw();

	// .. if we actually created it, we're really primary! Otherwise, let's just return and do nothing more.
	if (dwLastError == ERROR_ALREADY_EXISTS) {
		OutputDebugString(_T("Someone else is primary"));
		return 0;
	}

	// The only case when this
	// is not true, is if the master is killed, and we have secondaries
	// still alive. This can be fixed by introducing yet another Mutex
	// that is always owned by the master.
	mfIsPrimary = true;
	PrimaryInit(nCmdShow);

	// We are now the master server process, waiting for requests for action
	// through the shared memory map - signalled through SendEvent semaphore.
	while (TRUE) {
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			if (msg.message == WM_QUIT) {
				// ... then clean up etc.
				PrimaryPrepareForExit();
				return (int)msg.wParam;
			}
			else {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
		if (MsgWaitForMultipleObjects(1,
			&ghSendEvent,
			FALSE,
			INFINITE,
			QS_ALLINPUT) == (WAIT_OBJECT_0)) {
			PrimaryEvent();
#ifdef  _DEBUGPLUS
			{
				// Use this code to check heap alloc requirements
				static size_t stMaxAlloc;
				size_t stCurAlloc = pgHeap->CurrentAlloc();
				if (stCurAlloc > stMaxAlloc) {
					stMaxAlloc = stCurAlloc;
					TCHAR szAlloc[100];
					sprintf(szAlloc, "New max alloc=%d", stMaxAlloc);
					MessageBox(NULL, szAlloc, CVersion().String(), MB_OK);
				}
			}
#endif  _DEBUGPLUS
		}
	}
}

static bool GetMutex() {
	if (MessageWaitForSingleObject(ghMutex, MAX_WAIT_PRIMARY) != WAIT_OBJECT_0) {
		return false;
	}
	return true;
}

static void ReleaseMutex() {
	CAssert(ReleaseMutex(ghMutex)).Sys(MSG_SYSTEM_CALL, _T("ReleaseMutex [ReleaseMutex(ghMutex)]")).Throw();
}

//
//  Call the main process for action
//
//  If return is FALSE; error occurred and *pdwExitCode is set.
//
//  Secondary Main Thread
//
static BOOL
SecondaryExecuteRequest(SRequest* pRequest, DWORD* pdwExitCode) {
	*pdwExitCode = 0;
	try {
		// Get exclusive access to the request buffer. We actually do not assert here, since this is the secondary instance
		// a failure to get the mutex at this point probably means the primary died - or even more likely never got started.
		// Users get confused by two messages, so we just quietly exit with an error code here.
		if (!GetMutex()) {
			// If, GetLastError() for whatever reason returns ERROR_SUCCESS here, it's still an error so
			// we return our own non-1, non-0 return code.
			if (!(*pdwExitCode = GetLastError())) {
				*pdwExitCode = ERR_UNSPECIFIED;
			}
			return FALSE;
		}

		// Now get the primary process id.
		ZeroMemory(glpSRequest, sizeof * glpSRequest);
		glpSRequest->eRequest = EN_GETPROCID;
		CAssert(SetEvent(ghSendEvent)).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [SetEvent(ghSendEvent)]")).Throw();
		CAssert(MessageWaitForSingleObject(ghReceiveEvent, MAX_WAIT_EVENT) == WAIT_OBJECT_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [EN_GETPROCID]")).Throw();

		// Now we know the primary process id. Lets open a handle to it.
		DWORD dwPrimaryProcessId = glpSRequest->dwPrimaryProcessId;
		CHandle hPrimaryProcess = OpenProcess(PROCESS_DUP_HANDLE | SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, dwPrimaryProcessId);

		// SYNCHRONIZE is 2k+ specific, and P_Q_I is only needed on 2k+, so if the above fails, lets try:
		if (hPrimaryProcess == NULL) {
			hPrimaryProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwPrimaryProcessId);
		}

		if (hPrimaryProcess == NULL) {
			// This has been the source of many errors, unclear why at times we can't get the hPrimaryProcess. However - we don't really need
			// it, so let's be a bit tolerant and just log it here, and check below if we have it.
			CMessage().AppMsg(INF_DEBUG, _T("SecondaryExecuteRequest [hPrimaryProcess == NULL]")).LogEvent(2);
		}

		// Get the new request into the global request buffer.
		*glpSRequest = *pRequest;

		// Get handle to stdout into the the global request buffer, if possible
		//
		// It's not possible to duplicate console handles to other processes, and...
		// ...GUI process are not created with a console, and are not attached to a
		// console even when started from the command prompt. Thus, we must check
		// that we have a valid stdout before passing it.
		// This handle is used to output the id string for example from the primary process. An alternative
		// in the future is to let the secondary get the info instead, and use it's own handle.
		// The main process will close the handle passed to it, if any.
		HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hPrimaryProcess == NULL || hStdOut == INVALID_HANDLE_VALUE ||
			GetFileType(hStdOut) != FILE_TYPE_DISK &&
			GetFileType(hStdOut) != FILE_TYPE_PIPE) {
			glpSRequest->hStdOut = INVALID_HANDLE_VALUE;
		}
		else {
			CAssert(DuplicateHandle(GetCurrentProcess(), hStdOut, hPrimaryProcess, &glpSRequest->hStdOut, 0, FALSE, DUPLICATE_SAME_ACCESS)).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [DuplicateHandle()]")).Throw();
		}

		// We're having trouble with accessing the primary process, so lets be as tolerant as possible here.
		if (hPrimaryProcess == NULL) {
			// We could not get a handle with PROCESS_DUP_HANDLE apparently, so let's go for just SYNCHRONIZE|P_Q_I
			hPrimaryProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, dwPrimaryProcessId);
		}

		// Pass our current directory (reserve room for extra backslash).
		// TODO: This is really not the best way to solve the problem. The situation is that we want a different process
		// to find a file path located according to the context of this process. The best way is likely to interpret relative
		// paths here, and always pass fully qualified paths to the other process as well as the user-specified path - which
		// will then only be used for messages - i.e. a 'display'-name, since we do want to refer to it as the user sees it
		// in informative messages. This should be the strategy for version 2.
		DWORD dwLen;
		CAssert((dwLen = GetCurrentDirectory(sizeof glpSRequest->szCurDir / sizeof glpSRequest->szCurDir[0] - 1, glpSRequest->szCurDir)) != 0)
			.Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest() [GetCurrentDirectory()]"))
			.Throw();
		if (glpSRequest->szCurDir[dwLen - 1] != _T('\\')) {
			glpSRequest->szCurDir[dwLen++] = _T('\\');
			glpSRequest->szCurDir[dwLen] = _T('\0');
		}

		glpSRequest->CallerProcId = GetCurrentProcessId();

		// Disable foreground window handing in server mode
		if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
			glpSRequest->hCurWnd = NULL;
		}
		else {
			glpSRequest->hCurWnd = GetForegroundWindow();
		}

		CAssert(SetEvent(ghSendEvent)).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [SetEvent(ghSendEvent) (2)]")).Throw();

		// We need to process messages in this thread as well
		// Wait for main thread to acknowledge reception of event and
		// start of new worker thread, if any.
		CAssert(MessageWaitForSingleObject(ghReceiveEvent, MAX_WAIT_EVENT) == WAIT_OBJECT_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [WaitForWorkerToStart]")).Throw();

		//
		// here we need to get hold of the thread id, wait for it after the release mutex
		// so that we stay in memory until all is done.
		//
		DWORD dwWorkerThreadId = glpSRequest->dwWorkerThreadId;
		HANDLE hWorkerThread = OpenThread(SYNCHRONIZE, FALSE, dwWorkerThreadId);
		ASSAPI(hWorkerThread != NULL);

		DWORD dwWorkerUniqueInternalId = glpSRequest->dwWorkerUniqueInternalId;

		// Let someone else have a go... Release the mutex, also signaling the primary instance we're ready to go.
		ReleaseMutex();

		// We'll wait for ever for the worker thread.
		CAssert(MessageWaitForSingleObject(hWorkerThread, INFINITE) == WAIT_OBJECT_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [MessageWaitForSingleObject(Threads)]")).Throw();
		CloseHandle(hWorkerThread);

		// There's a bug, or at least a large difference in behavior in Win98 (et.al. presumably).
		// When we do a GetExitCodeThread, the thread in question must specifically return an exit code.
		// In XP (et.al I guess), it does the sensible thing and assigns the process exit code to the
		// last thread as well. Since the secondary process gets its return code from the primary
		// thread, we need to ensure that if we know we have executed a command that causes the entire
		// process to exit, not just the thread, we must get the exit code from the process instead,
		// thus we special-case here. Sigh. Another wasted 6 hours.
		switch (pRequest->eRequest) {
			// It should only be exit which is relevant here
		case EN_EXIT:
			// Not even SYNCHRONIZE! Forget it and just exit.
			if (hPrimaryProcess == NULL) {
				*pdwExitCode = MSG_INTERNAL_ERROR;
				break;
			}
			CAssert(MessageWaitForSingleObject(hPrimaryProcess, INFINITE) == WAIT_OBJECT_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [MessageWaitForSingleObject(hPrimaryProcess)]")).Throw();
			CAssert(GetExitCodeProcess(hPrimaryProcess, pdwExitCode)).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [GetExitCodeProcess]")).Throw();
			break;
		default:
			// To avoid Access Denied problems, we won't try to get the exit code directly from the worker thread, but instead ask the
			// primary process to get it for us. It requires THREAD_QUERY_INFORMATION, and we won't always be able to get it.
			if (!GetMutex()) {
				*pdwExitCode = MSG_INTERNAL_ERROR;
				break;
			}
			glpSRequest->eRequest = EN_GETTHREADEXIT;
			glpSRequest->dwWorkerUniqueInternalId = dwWorkerUniqueInternalId;
			CAssert(SetEvent(ghSendEvent)).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [SetEvent(ghSendEvent) 2]")).Throw();
			DWORD dwReturnCode = MessageWaitForSingleObject(ghReceiveEvent, MAX_WAIT_EVENT);
			CAssert(dwReturnCode != WAIT_FAILED).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [EN_GETTHREADEXIT] WAIT_FAILED")).Throw();
			CAssert(dwReturnCode != WAIT_ABANDONED_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [EN_GETTHREADEXIT] WAIT_ABANDONED_0")).Throw();
			CAssert(dwReturnCode != WAIT_TIMEOUT).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [EN_GETTHREADEXIT] WAIT_TIMEOUT")).Throw();
			CAssert(dwReturnCode == WAIT_OBJECT_0).Sys(MSG_SYSTEM_CALL, _T("SecondaryExecuteRequest [EN_GETTHREADEXIT]")).Throw();
			*pdwExitCode = glpSRequest->dwExitCode;
			ReleaseMutex();
			break;
		}
	}
	catch (TAssert utErr) {
		(void)ReleaseMutex(ghMutex);
		// If we have a parameter, use a message were we show it.
		if (*pRequest->szParam1) {
			utErr.File(MSG_CMD_LINE_OPEN, pRequest->szParam1).Show();
		}
		else {
			// Otherwise use a more generic form.
			utErr.App(ERR_GENERIC_FUNC, _T("SecondaryExecuteRequest()")).Show();
		}
		*pdwExitCode = utErr.LastError();
	}
	return *pdwExitCode ? FALSE : TRUE;
}

/// \brief Check if, and perform, immediate commands
///
/// The immediate commands are 'PSP test', 'Install' and 'Uninstall'.
/// \param dwExitCode The exit code to return is returned here.
static bool
ParseImmediateCommand(int nCmdShow, DWORD* pdwExitCode) {
	TCHAR chOpt;
	optind = 0;
	optarg = NULL;
	chOpt = (TCHAR)mygetopt(tArgc, tArgv, _T("i:pu"));

	if (chOpt == _T('?') || chOpt == (TCHAR)-1) {
		// Not one of our options.
		return false;
	}

	// Do a best effort attempt to have the primary process, if any, exit
	SRequest Request;
	ZeroMemory(&Request, sizeof Request);
	Request.eRequest = EN_EXIT;
	DWORD dwIgnoredExitCode;
	SecondaryExecuteRequest(&Request, &dwIgnoredExitCode);

	// Now, if we're running Vista, and we're running in non-elevated mode, we relaunch ourselves yet another
	// time as an elevated process, since these options require elevation to administrator. This could be extended
	// to older OS's as well when not running as admin, but we'll leave that for now. The real reason we need this
	// is to be able to test without running the installer (which also has the capability as of now, although this
	// may change in the future, once again causing this to be needed).
	if (awl::IsVistaOrLater()) {
		if (awl::RelaunchElevatedOnVista(pdwExitCode, NULL, nCmdShow)) {
			return true;
		}
	}

	CCmdParam utCmdParam;
	switch ((TCHAR)chOpt) {
	case _T('i'):
		if (tArgc > (2 + (optarg != NULL ? 1 : 0))) {
			CMessage().AppMsg(MSG_UNKNOWN_OPT, tArgv[tArgc - 1]).ShowError();
			*pdwExitCode = MSG_UNKNOWN_OPT;
			return true;
		}

		utCmdParam.eRequest = EN_INSTALL;
		if (optarg != NULL) {
			utCmdParam.szParam1 = optarg;
		}

		*pdwExitCode = CmdInstallInRegistry(&utCmdParam);     // Just setup registry etc.
		break;
	case _T('p'):
		if (tArgc > 2) {
			CMessage().AppMsg(MSG_UNKNOWN_OPT, tArgv[2]).ShowError();
			*pdwExitCode = MSG_UNKNOWN_OPT;
			return true;
		}
		*pdwExitCode = CChildProc().NeedPsapi() ? 1 : 0;
		break;
	case _T('u'):
		if (tArgc > 2) {
			CMessage().AppMsg(MSG_UNKNOWN_OPT, tArgv[2]).ShowError();
			*pdwExitCode = MSG_UNKNOWN_OPT;
			return true;
		}
		utCmdParam.eRequest = EN_UNINSTALL;
		*pdwExitCode = CmdRemoveFromRegistry(&utCmdParam);
		break;
	default:
		CMessage().AppMsg(MSG_UNKNOWN_OPT, tArgv[optind - 1]).ShowError();
		*pdwExitCode = MSG_UNKNOWN_OPT;
		return true;
	}
	return true;
}

//
// Parse command line for action - This is never done in the primary instance.
//
// -b nnnnn             Define the batch that this command is part of.
// -t                   Clear all keys (of a batch if given, otherwise all keys).
// -i                   Install application
// -u                   Uninstall application
// -x                   Exit the application - mostly for testing purposes
// -p                   Test for need to install psapi.dll
// -c filename(s)       Encrypt and Wrap, do not wipe original.
// -d filename(s)       Decrypt and Unwrap, do not open
// -w filename(s)       Wipe
// (-o) filename(s)     Open and Launch
//
// "Secondary Main Thread"
//
//
static  DWORD
SecondaryParseCommand() {
	DWORD dwExitCode = 0;
	try {
		SRequest Request;
		ZeroMemory(&Request, sizeof Request);

		enum eRequestType eRequest = EN_OPEN;

		// Get the global persistent default for wipe passes
		Request.nWipePasses = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValWipePasses).GetDword(1);

		TCHAR chOpt;
		LPTSTR szOutFileName = NULL, szIdTag = NULL, szBruteForceCheck = NULL, szApp2Use = NULL;
		BOOL fAddKeyEncrypt = FALSE;
		// Read default fast-mode from the registry. Super-default is 'FALSE'.
		BOOL fFast = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValFastModeDefault).GetDword(FALSE);
		BOOL fCopy = FALSE;
		optind = 0;
		optarg = NULL;
		do {
			chOpt = mygetopt(tArgc, tArgv, _T("ab:cdefghi:Jk:K:lL:mn:O:opqrR:stuv:V:wxy:Yz"));
			if (optarg) {
				lstrcpyn(Request.szParam1, optarg, sizeof Request.szParam1 / sizeof Request.szParam1[0]);
			}
			else {
				Request.szParam1[0] = _T('\0');
			}
			switch (chOpt) {
			case _T('a'):   // Ask for key
				Request.eRequest = fAddKeyEncrypt ? EN_ASKKEYENC : EN_ASKKEYDEC;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					return dwExitCode;
				}
				break;
			case _T('b'):   // Batch id.
				Request.dwBatch = _ttol(optarg);
				break;
			case _T('c'):
				// Toggle copy-instead flag.
				fCopy = !fCopy;
				break;
			case _T('d'):
				// First check for disabled decryption mode
				if (gfNoDecryptMode) {
					CMessage().AppMsg(MSG_UNKNOWN_OPT, _T("-d")).ShowError();
					return MSG_UNKNOWN_OPT;
				}

				// Decrypt, depending on fast and copy flags.
				if (fCopy) {
					if (fFast) {
						eRequest = EN_DECRYPTCF;
					}
					else {
						eRequest = EN_DECRYPTC;
					}
				}
				else {
					if (fFast) {
						eRequest = EN_DECRYPTF;
					}
					else {
						eRequest = EN_DECRYPT;
					}
				}
				break;
			case _T('e'):
				fAddKeyEncrypt = TRUE;
				break;
			case _T('f'):
				fFast = !fFast;
				break;
			case _T('g'):
				Request.fIgnoreEncrypted = !Request.fIgnoreEncrypted;
				break;
			case _T('h'):
				eRequest = EN_RENAME;
				break;
			case _T('i'):
				Request.eRequest = EN_INSTALL;
				SecondaryExecuteRequest(&Request, &dwExitCode);

				return dwExitCode;
			case _T('J'):
				// For SFX the default should be to ignore encrypted. As the global
				// default is 'FALSE' above, this is adjusted there. This will work
				// fine together with -g as well.
				Request.fIgnoreEncrypted = !Request.fIgnoreEncrypted;
				eRequest = EN_SFXENCNEW;
				break;
			case _T('k'):   // Add key
				Request.eRequest = fAddKeyEncrypt ? EN_ADDKEYENC : EN_ADDKEYDEC;
				_tcsset_s(optarg, _tcslen(optarg) + 1, _T('*'));

				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					ZeroMemory(&Request, sizeof Request);
					return dwExitCode;
				}
				ZeroMemory(Request.szParam1, sizeof Request.szParam1);
				break;
			case _T('K'): // Generate a key-file and save it. If there's no
						// file name, we ask for it.
				Request.eRequest = EN_MAKEKEYFILE;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					return dwExitCode;
				}
				break;
			case _T('l'): // Launch the license dialog
				Request.eRequest = EN_LICENSEMGR;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					return dwExitCode;
				}
				break;

			case _T('L'): // Launch the registration dialog
				Request.eRequest = EN_REGISTRATION;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					return dwExitCode;
				}
				break;

			case _T('m'):
				Request.fRecurseDir = !Request.fRecurseDir;
				break;
			case _T('n'):
				szOutFileName = optarg;
				break;
			case _T('O'):
				// Remember application to use string
				szApp2Use = optarg;
				break;
			case _T('o'):
				eRequest = EN_OPEN;
				break;
			case _T('p'):
				Request.eRequest = EN_PSPTEST;
				SecondaryExecuteRequest(&Request, &dwExitCode);
				return dwExitCode;
			case _T('q'):
				eRequest = EN_TESTHAVEKEY;
				break;
			case _T('R'): // Try to brute force, re-starting from last check-point.
				if (!*(szBruteForceCheck = optarg)) {
					// Pick up check-point from registry
				}
				// Fall through
			case _T('r'): // Try to brute force, starting from scratch.
				eRequest = EN_BRUTEFORCE;
				break;
			case _T('s'):
				eRequest = EN_WIPES;
				break;
			case _T('t'):
				Request.eRequest = EN_CLEARKEYS;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					return dwExitCode;
				}
				break;
			case _T('u'):
				Request.eRequest = EN_UNINSTALL;
				SecondaryExecuteRequest(&Request, &dwExitCode);
				return dwExitCode;
			case _T('V'):
				// Set the persistent default number of passes for wipe. Zero means default '1'.
				Request.nWipePasses = _ttol(optarg);

				// Store this in the registry
				CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey).Value(szRegValWipePasses).SetDword(Request.nWipePasses);
				break;
			case _T('v'):
				// Set the current override for the rest of the command-line for number of passes for wipe.
				Request.nWipePasses = _ttol(optarg);
				break;
			case _T('w'):
				eRequest = EN_WIPE;
				break;
			case _T('x'):
				Request.eRequest = EN_EXIT;
				SecondaryExecuteRequest(&Request, &dwExitCode);
				return dwExitCode;
			case _T('y'):
				// IdTag.
				// Valid only on encryption, it cannot be set on encrypted files.
				// Potentially it can be implemented if the key is known.
				// It is retained unchanged on -o with re-encryption.
				szIdTag = optarg;
				break;
			case _T('Y'):   // Show tag if any of following encrypted files.
				eRequest = EN_SHOWTAG;
				break;
			case _T('z'):
				// Encrypt, depending on fast and copy flags.
				if (fCopy) {
					if (fFast) {
						eRequest = EN_ENCRYPTZCF;
					}
					else {
						eRequest = EN_ENCRYPTZC;
					}
				}
				else {
					if (fFast) {
						eRequest = EN_ENCRYPTZF;
					}
					else {
						eRequest = EN_ENCRYPTZ;
					}
				}
				break;
			case (TCHAR)-1:    // Execute currently valid request option
				// If we don't have an optarg - we're out of arguments.
				if (optarg == NULL) {
					return 0;
				}
				else {
					optind++;
				}
				// Set output filename parameter for those options that take one.
				// Or other options.
				switch (eRequest) {
				case EN_BRUTEFORCE:
					if (szBruteForceCheck != NULL) {
						lstrcpyn(Request.szParam2, szBruteForceCheck, sizeof Request.szParam2 / sizeof Request.szParam2[0]);

						szBruteForceCheck = NULL;
					}
					break;
				case EN_OPEN:
					// Send the open-with string to the Open code.
					if (szApp2Use != NULL) {
						lstrcpyn(Request.szParam2, szApp2Use, sizeof Request.szParam2 / sizeof Request.szParam2[0]);
					}
					break;

				case EN_ENCRYPTZ:
				case EN_ENCRYPTZC:
				case EN_ENCRYPTZCF:
				case EN_SFXENCNEW:
				case EN_SFXENCAPP:
					if (szIdTag != NULL) {
						lstrcpyn(Request.szIdTag, szIdTag, sizeof Request.szIdTag / sizeof Request.szIdTag[0]);
					}
					// fall through...!
				case EN_DECRYPT:
				case EN_DECRYPTC:
				case EN_DECRYPTCF:
				case EN_SHOWTAG:
					if (szOutFileName != NULL) {
						lstrcpyn(Request.szParam2, szOutFileName, sizeof Request.szParam2 / sizeof Request.szParam2[0]);
						szOutFileName = NULL;
					}
					break;
				default:
					Request.szParam2[0] = _T('\0');
				}
				Request.eRequest = eRequest;
				if (!SecondaryExecuteRequest(&Request, &dwExitCode)) {
					// We continue file processing, even if a request was just ignored.
					if (dwExitCode != INF_YESALL) {
						if (dwExitCode != WRN_IGNORED) {
							return dwExitCode;
						}
						dwExitCode = 0;	// Clear the WRN_IGNORED if this is the last file so the operation succeeds even with ignored files.
					}
				}
				break;
			case _T('?'):
				CMessage().AppMsg(MSG_UNKNOWN_OPT, tArgv[optind - 1]).ShowError();
				return MSG_UNKNOWN_OPT;
			}
			Request.szParam1[0] = _T('\0');
		} while (optind < tArgc);
	}
	catch (TAssert utErr) {
		utErr.App(MSG_PARSE_COMMAND_INTERNAL).Show();
		return utErr.LastError();
	}
	return dwExitCode;
}

/// \brief Set and prepare for setting of security of various kernel objectgs
/// Since we may be runas - particularily during an install, we need to modify the
/// default protection of our process, mutex, events and shared memory. This
/// code prepares for, and does, that.
/// Quietly accept "Not Implemented" errors on the assumption that we don't need the effect of the call either in that case.
/// This is actually once again a case of very unclear MS Documentation. According to that, these calls should not even be
/// there in for examle Win98 - but they are and will return an error instead. Sigh. This means that they have changed the behavior
/// of older operating systems as new has arrived, presumably in effect breaking old legacy apps.
void
SetSecurity() {
	// These do not need to be visible by name anywhere, but to just avoid having to free them
	// we have them as statics here. No big waste of space...
	static SECURITY_ATTRIBUTES NullSecurityAttributes;
	static SECURITY_DESCRIPTOR SecurityDescriptor;

	// Build a set of null (everyone full access) security attributes
	ZeroMemory(&NullSecurityAttributes, sizeof NullSecurityAttributes);
	NullSecurityAttributes.nLength = sizeof NullSecurityAttributes;
	NullSecurityAttributes.bInheritHandle = FALSE;

	ASSAPI(InitializeSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION) || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
	if (GetLastError() != ERROR_CALL_NOT_IMPLEMENTED) {
		// Now we assign a NULL DACL to the SD
		ASSAPI(SetSecurityDescriptorDacl(&SecurityDescriptor, TRUE, (PACL)NULL, FALSE) || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);

		// Refer to it in our security attributes - now we have a nice standard allow all to everyone
		// security attributs structures to use.
		NullSecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;

		// Finally set a valid pointer for the rest of the code to use.
		gpNullSecurityAttributes = &NullSecurityAttributes;
	}

	// Ensure that other users can syncrhonize and work with us - specifically get a process handle
	// It's different if we're primary or secondary - but let's fix that later.
	ACL* pdacl = NULL;
	PSID psidWorldSid = NULL;
	do { // once - cheap 'try'.
		// Create a world SID, the hard way with the proper good old calls, to ensure compatibility with various windowses.
		psidWorldSid = (PSID)LocalAlloc(LPTR, GetSidLengthRequired(1));
		ASSPTR(psidWorldSid);
		SID_IDENTIFIER_AUTHORITY siaWorldSidAuthority = SECURITY_WORLD_SID_AUTHORITY;

		ASSAPI(InitializeSid(psidWorldSid, &siaWorldSidAuthority, 1) || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
		if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
			break;
		}

		// There is no extended error info here... They could not be satisfied with one way of returning errors could they ?
		if (!IsValidSid(psidWorldSid)) {
			ASSPTR(NULL);
		}

		// There appears to be no proper way to check the result, so we can just validate it above and
		// hope for the best. On error the return is undefined, and on success it appears that GetLastError()
		// is not valid. Sigh. Doesn't anyone actually use these calls at MS? How can they write safe code?
		(*GetSidSubAuthority(psidWorldSid, 0)) = SECURITY_WORLD_RID;

		/*
				// Do this the hard way, with old NT calls only... Build an ACL and then add it as an AccessAllowedAcl.
				DWORD dwAclLength = sizeof ACL + sizeof ACCESS_ALLOWED_ACE - sizeof DWORD + pfGetLengthSid(psidWorldSid);
				pdacl = (ACL *)LocalAlloc(LPTR, dwAclLength);
				ASSPTR(pdacl);
				ZeroMemory(pdacl, dwAclLength);
				ASSAPI(pfInitializeAcl(pdacl, dwAclLength, ACL_REVISION) != 0 || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
				if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
					break;
				}

				ASSAPI(pfAddAccessAllowedAce(pdacl, ACL_REVISION, PROCESS_DUP_HANDLE|SYNCHRONIZE|PROCESS_QUERY_INFORMATION|PROCESS_TERMINATE|PROCESS_SET_INFORMATION, psidWorldSid) != 0 || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
				if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED) {
					break;
				}
		*/
		// So why not just use the GetCurrentProcces() pseudo-handle? Because Windows NT 4.0 will not allow the SetSecurityInfo
		// using that as a handle. Sigh. Wouldn't it have been nice to mention this slight detail in the documentation? The other
		// versions of windows are happy with the pseudo-handle, which is also in line with the docs.
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, GetCurrentProcessId());
		ASSAPI(hProc != NULL);

		//PSECURITY_DESCRIPTOR pSecurityDescriptor;
		//ASSAPI(GetSecurityInfo(hProc, SE_KERNEL_OBJECT, 0, NULL, NULL, NULL, NULL, &pSecurityDescriptor) == ERROR_SUCCESS);
		//SECURITY_DESCRIPTOR_CONTROL pControl;
		//DWORD dwRevision;
		//ASSAPI(GetSecurityDescriptorControl(pSecurityDescriptor, &pControl, &dwRevision);
		//ASSAPI(SetSecurityDescriptorControl(pSecurityDescriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED));
		//LocalFree(pSecurityDescriptor);

		// This is soo unbelievably frustrating... Why can't they document properly and clearly? Ok, so SetSecurityInfo docs do
		// not explicitly state that it sets LastError, then again it does not explicitly state that it does not. Worse - the behavior
		// varies from versions of Windows... In NT, it does *not* set LastError, but does return the proper error code.
		PACL pOriginalAcl;
		PSECURITY_DESCRIPTOR pSecurityDescriptor;
		GetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOriginalAcl, NULL, &pSecurityDescriptor);

		// The following code is simpler and cleaner, but was modified searching for the trouble with the SetSecurityInfo() call
		// on Windows NT 4.0 - see below. I'll keep it around for a while for reference - it's much nicer.
		EXPLICIT_ACCESS ea =
		{
			PROCESS_DUP_HANDLE | SYNCHRONIZE | PROCESS_QUERY_INFORMATION, //PROCESS_ALL_ACCESS,
			GRANT_ACCESS,
			NO_INHERITANCE,
			{
				NULL,
				NO_MULTIPLE_TRUSTEE,
				TRUSTEE_IS_SID,
				TRUSTEE_IS_GROUP,
				reinterpret_cast<LPTSTR>(psidWorldSid)
			}
		};
		ASSAPI(SetEntriesInAcl(1, &ea, pOriginalAcl, &pdacl) == ERROR_SUCCESS || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);

		LocalFree(pSecurityDescriptor);

		SetLastError(SetSecurityInfo(hProc, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pdacl, NULL));
		ASSAPI(GetLastError() == ERROR_SUCCESS || GetLastError() == ERROR_CALL_NOT_IMPLEMENTED);
		ASSAPI(CloseHandle(hProc));
	} while (false);
	LocalFree(pdacl);
	LocalFree(psidWorldSid);
}

//
// Start here - Split depending on first instance or not. The first
// instance sets itself up as a server, secondary instances call it.
//
//  If we have no first, or primary, instance we launch a new process
//  for it. The primary is loaded by calling with no parameters.
//  It's ok to try multiple times, in that case it's just a noop.
//
int APIENTRY
WinMainInternal(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	// This sucks a bit - how come they didn't implement generic text mapping here, i.e. __targc et. al.?
#if defined(_UNICODE) || defined(UNICODE)
	tArgv = CommandLineToArgvW(GetCommandLineW(), &tArgc);
#else
	tArgv = tArgv;
	tArgc = tArgc;
#endif

	AxPipe::CGlobalInit axpipeInit;         // It just has to be there to initialize global things.

	int iReturn = 0;
	HANDLE hRequestFileMap = NULL;

	InitCommonControls();
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	// Set up for messages and logging
	const _TCHAR* szMsg = InitGlobalStrings(ghInstance = hInstance);
	if (szMsg != NULL) {
		ASSCHK(FALSE, szMsg);
	}

	// Setup for security modifications
	SetSecurity();

	// Will be called in reverse order
	atexit(DestroyGlobals2);            // Last of all goes the entropy pool
	atexit(CleanTmp);                   // We still need entropy to wipe the heap
	atexit(DestroyGlobals1);            // All but the entropy pool
	atexit(UnInitGlobalStrings);

	try {
		// Common initialization, regardless of primary or secondary
		// We create/open two Events (one to send, one to acknowledge reception) and
		// a file mapping view to handle the request communication. If the file mapping already
		// exists, we assume that is because we are a secondary instance.
		CAssert((ghSendEvent = CreateEvent(gpNullSecurityAttributes, FALSE, FALSE, gszAxCryptEventSend)) != NULL).Sys(MSG_CREATE_EVENT, gszAxCryptEventSend).Throw();
		CAssert((ghReceiveEvent = CreateEvent(gpNullSecurityAttributes, FALSE, FALSE, gszAxCryptEventReceive)) != NULL).Sys(MSG_CREATE_EVENT, gszAxCryptEventReceive).Throw();
		CAssert((hRequestFileMap = CreateFileMapping((HANDLE)~0,
			gpNullSecurityAttributes,
			PAGE_READWRITE,
			0,
			sizeof SRequest,
			gszAxCryptFileMap)) != NULL).App(MSG_CREATE_REQUEST_MAP, gszAxCryptFileMap).Throw();
		CAssert((glpSRequest = (SRequest*)MapViewOfFile(hRequestFileMap,
			FILE_MAP_WRITE,
			0, 0,
			sizeof SRequest)) != NULL).App(MSG_CREATE_REQUEST_MAP, gszAxCryptFileMap).Throw();

		// If a commandline, then we parse command and call primary.
		if (tArgc > 1) {
			// Try and possibly execute the commands we perform right here and now.
			DWORD dwExitCode;
			if (ParseImmediateCommand(nCmdShow, &dwExitCode)) {
				iReturn = dwExitCode;
			}
			else {
				// Ensure that the primary is started
				ghMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, gszAxCryptMutex);
				// If we couldn't open the mutex, we need a primary process
				if (ghMutex == NULL) {
					STARTUPINFO stStartupInfo;
					ZeroMemory(&stStartupInfo, sizeof stStartupInfo);
					stStartupInfo.cb = sizeof stStartupInfo;
					PROCESS_INFORMATION stProcessInformation;
					ZeroMemory(&stProcessInformation, sizeof stProcessInformation);

					CAssert(CreateProcess(
						NULL,
						(LPWSTR)(CFileName().SetPath2ExeName(hInstance).GetQuoted()),
						NULL,
						NULL,
						FALSE,
						0,
						NULL,
						NULL,
						&stStartupInfo,
						&stProcessInformation)).Sys(MSG_SYSTEM_CALL, _T("CreateProcess() [WinMain()]")).Throw();

					WaitForInputIdle(stProcessInformation.hProcess, MAX_WAIT_PRIMARY);
					CAssert(CloseHandle(stProcessInformation.hThread)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle() [WinMain() .hThread]")).Throw();
					CAssert(CloseHandle(stProcessInformation.hProcess)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle() [WinMain() .hProcess]")).Throw();

					// Now we should be able to open the mutex, but there have been reports of problems
					// so we'll try really hard. This is kind of ugly, in the future we should fix
					// this. Don't know why we ended up with this mess, it should be created/opened
					// always by the caller, and then taking action from there. I.e. - if it was
					// created by a secondary instance _then_ we initate a primary etc. Let's fix
					// that for version 2.0. Not to be forgotten is that the caller of Xecrets File
					// should always be able to wait on the instance that gets started, thus if
					// we get called, and need to start a primary instance, that must be 'secondary'
					// to the one called.
					for (int i = 0; (ghMutex == NULL) && (i < 5); i++) {
						ghMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, gszAxCryptMutex);
						if (ghMutex == NULL) {
							Sleep(MAX_SLEEP_PRIMARY);
						}
					}
				}
				CAssert(ghMutex != NULL).Sys(MSG_SYSTEM_CALL, _T("OpenMutex() [WinMain()]")).Throw();
				iReturn = SecondaryParseCommand();
			}
		}
		else {
			iReturn = PrimaryProcess(nCmdShow);
		}
	}
	catch (TAssert utErr) {
		OutputDebugString(_T("Catching unhandled exception in WinMainInternal"));
		utErr.App(MSG_WINMAIN).Show();
		iReturn = utErr.LastError();
	}
	// Close all open handles etc
	if (ghSendEvent) CloseHandle(ghSendEvent);
	if (ghReceiveEvent) CloseHandle(ghReceiveEvent);
	if (ghMutex) CloseHandle(ghMutex);
	if (glpSRequest) UnmapViewOfFile(glpSRequest);
	if (hRequestFileMap) CloseHandle(hRequestFileMap);

	CoUninitialize();
	return iReturn;
}

int APIENTRY
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	// This is an attempt to be able to mix RegOpenCurrentUser() with HKCU useage.
	::RegDisablePredefinedCache();
	int iReturn = 1;
	try {
		iReturn = WinMainInternal(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
	}
	catch (TAssert utErr) {
		OutputDebugString(utErr.GetMsg().Ptr());
		iReturn = utErr.LastError();
	}
	return iReturn;
}