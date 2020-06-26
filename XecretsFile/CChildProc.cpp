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
	CChildProc.cpp                  Utility functions of a more esoteric nature, doing the
									things that really should just require some simple API
									calls, but that for unknown reasons the designers of
									win32 still has not realized, even now when they are
									launching the fourth version of it! I mean, really,
									should you need to implement a process handle-to process
									id mapping by using side effects of the performance
									library?
									Unfortunately there is some OS-dependent code here, and
									even a few sort-of undocumented calls, at least calls
									that are not part of the Win32 API as such.

	E-mail                          YYYY-MM-DD              Reason
	software@axantum.com             2001                    Initial

*/
#include    "StdAfx.h"
#include    "CChildProc.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CChildProc.cpp"

CChildProc::CChildProc() {
	m_hWndThread = NULL;
	InitFunctionPointers();
}

CChildProc::CChildProc(DWORD dwProcId, const TCHAR *szExecName) {
	m_hWndThread = NULL;
	InitFunctionPointers();
	Mark(dwProcId, szExecName);
}

CChildProc::~CChildProc() {
	if (m_hPSAPI) FreeLibrary(m_hPSAPI);
}
//
//  Create the object with an initial snapshot of the current kids
//  of the given process, as well as the current threads of the
//  likely candidates if the process that will be used in the end
//  is already started.
//
void
CChildProc::Mark(DWORD dwProcId, const TCHAR *szExecFile) {
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::Mark() [GetCurrentThreadId()]"), GetCurrentThreadId()).LogEvent(2);
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::Mark() [szExecFile]"), szExecFile).LogEvent(2);
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::Mark() [dwProcId]"), dwProcId).LogEvent(2);
	if (szExecFile) {
		m_szExecFile = szExecFile;
	}
	// Get the current child processes of the given process ID
	m_SetOfMarkProc.clear();
	m_SetOfDiffProc.clear();
	// Truly ugly, a quick and very dirty way to fix so that we store all current processes in the mark-set.
	// See the comment in AddNewChildProcesses for further rationale behind this.
	m_dwPProcessId = 0;
	AddNewChildProcesses(m_SetOfDiffProc, m_SetOfMarkProc);
	m_dwPProcessId = dwProcId;

	// Get all likely thread-candidates into the set for the mark
	m_ThreadDiff.clear();
	AddNewThreads(m_ThreadDiff, m_ThreadMark, NULL);

	// Get the current state of visible windows too...
	m_SetOfMarkHwnd.clear();
	m_SetOfDiffHwnd.clear();
	AddNewWindows(m_SetOfDiffHwnd, m_SetOfMarkHwnd);
}
//
// Take a new snapshot, compare with old, and store the diff, incrementally
//
void
CChildProc::Diff(bool fIgnoreParent, HWND hWndForeground) {
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::Diff() [GetCurrentThreadId()]"), GetCurrentThreadId()).LogEvent(2);
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::Diff() [hWndForeground]"), (int)(INT_PTR)hWndForeground).LogEvent(2);

	// Get the current child processes of the given process ID
	// If fIgnoreParent is true here, the idea is that we should only find children of the already found
	// children, i.e. the ones that already are in m_SetOfDiffProc (but not in the m_SetOfMarkProc set)
	AddNewChildProcesses(m_SetOfMarkProc, m_SetOfDiffProc, fIgnoreParent);

	// Get all likely thread-candidates into the set for the diff
	AddNewThreads(m_ThreadMark, m_ThreadDiff, hWndForeground);

	// Check if any new visible windows have appeared on the scene
	AddNewWindows(m_SetOfMarkHwnd, m_SetOfDiffHwnd);
}
//
// If at least one child process was found
//
bool
CChildProc::ProcessFound() {
	return !m_SetOfDiffProc.empty();;
}
//
// If at least one likely new thread or window was found
//
bool
CChildProc::ThreadFound() {
	return !m_ThreadDiff.empty() || !m_SetOfDiffHwnd.empty();
}
//
// Wait for all processes to go input idle
//
void
CChildProc::WaitForInputIdle(const TCHAR *szFileName) {
	// What can happen here is that several processes are started as the result of a document opening. Not necessarily
	// all of them may have a message queue. Specifically, Open Office once again does tricky things, and starts up to
	// three processes, one of which (typically swriter.exe) will not return until the timeout from ::WaitForInputIdle().
	// Since we really don't know what is happening, we'll relax the requirement from having *all* processes achieving
	// InputIdle, to *any* process doing so.
	dwSetT::size_type failedWaitCount = 0;
	DWORD totalTimeOut = 5000;
	for (dwSetT::iterator it = m_SetOfDiffProc.begin(); it != m_SetOfDiffProc.end(); ++it) {
		CHandle hAppProc = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, *it);
		if (hAppProc.IsValid()) {
			// Give the process up to 5 seconds to load etc.
			DWORD startTime = ::GetTickCount();
			DWORD dwWaitReturn = ::WaitForInputIdle(hAppProc, totalTimeOut);
			// This should work even if a wrap around occurs, due to twos complement magic
			DWORD elapsedTime = ::GetTickCount() - startTime;
			if (elapsedTime > totalTimeOut) {
				totalTimeOut = 0;
			}
			else {
				totalTimeOut -= elapsedTime;
			}
			if (dwWaitReturn == WAIT_TIMEOUT) {
				++failedWaitCount;
			}
			else {
				// The MS Documentation does not state correctly what happens if the process
				// is a console app or without message queue. In this case, WaitForInputIdle() may
				// return WAIT_FAILED - but no error code from GetLastError(), this should be treated
				// as a successful wait in this case. [BUG 993814]
				CAssert((dwWaitReturn == 0) || (GetLastError() == ERROR_SUCCESS)).Sys().Throw();
				// The wait can terminate successfully because:
				//
				//	1 - The process terminated
				//	2 - The process really is InputIdle
				//
				//	We determine this by closing and reopening the process handle.
				CAssert(hAppProc.Close()).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(hAppProc) [LaunchApp(1)]")).Throw();
				hAppProc = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, *it);
			}
		}
		if (!hAppProc.IsValid()) {
			// Check that it was just an old proc id/no known child that was the problem.
			CAssert(GetLastError() == ERROR_INVALID_PARAMETER).Sys().Throw();
		}
	}
	if (failedWaitCount == m_SetOfDiffProc.size()) {
		CMessage().AppMsg(WRN_INPUT_IDLE_TIMEOUT, CFileName(szFileName).GetTitle()).ShowWarning(MB_OK);
	}
}
//
// Wait for all process to finish
//
void
CChildProc::WaitForProcess() {
	dwSetT::iterator it;
	for (it = m_SetOfDiffProc.begin(); it != m_SetOfDiffProc.end(); it++) {
		CHandle hAppProc = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, *it);
		if (hAppProc.IsValid()) {
			// Use the special utility MessageWait... to keep the message loop running
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::WaitForProcess [MessageWaitForSingleObject]"), *it).LogEvent();
			(void)MessageWaitForSingleObject(hAppProc);
		}
	}
}

/// \brief Wait for processes on the diff-list to exit, and also add new-come children and wait for them
void
CChildProc::WaitForProcessAndNewChildren() {
	dwSetT::iterator it;
	while (!m_SetOfDiffProc.empty()) {
		for (it = m_SetOfDiffProc.begin(); it != m_SetOfDiffProc.end(); it++) {
			CHandle hAppProc = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, *it);
			if (hAppProc.IsValid()) {
				// Use the special utility MessageWait... to keep the message loop running
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::WaitForProcess [MessageWaitForSingleObject]"), *it).LogEvent();
				// Let's wait with a rather short time-out. The purpose is to ensure that if we're waiting for more than one
				// process, there is short latency in finding that it has exited. This in turn is because we'd like to see if there are
				// new child processes of any of the ones we're waiting for, but since Windows is pretty fast with re-using process Id's
				// there's a race condition here (we don't want to get children of totally unrelated processes onto the wait-list),
				// we don't fix the race but hopefully we reduce the risk to close to nil. For this condition to happen now, a process Id
				// must be re-used and it in turn must start a child process in the space of the time-out below.
				if (MessageWaitForSingleObject(hAppProc, 50) != WAIT_TIMEOUT) {
					// Add new-comers, but only children of those on the new-list
					AddNewChildProcesses(m_SetOfMarkProc, m_SetOfDiffProc, true);

					// When the process is dead, we need to remove it from the wait-list, since it may be re-used.
					m_SetOfDiffProc.erase(it);
					break;
				}
			}
			else {
				m_SetOfDiffProc.erase(it);
				break;
			}
		}
	}
}
//
// Wait for all threads to finish and windows to disappear
//
void
CChildProc::WaitForThread() {
	while (true) {
		if (!m_ThreadDiff.empty() && CheckAllThreads(m_ThreadDiff)) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::WaitForThread() [CheckAllThreads()]"), GetCurrentThreadId()).LogEvent(1);
		}

		if (!m_SetOfDiffHwnd.empty() && CheckAllWindows(m_SetOfDiffHwnd)) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::WaitForThread() [CheckAllWindows()]"), GetCurrentThreadId()).LogEvent(1);
		}
		// This is getting to be less and less of an exact science... It turns out OpenOffice 1.1.3 (at least)
		// has the interesting behavior of keeping (an ever-increasing???) pool of threads in a hidden, window-less
		// process. When an OpenOffice document is opened, a new thread may or may not be created, and then a window
		// with the document. When the document closes, the window closes - but not the thread! So we keep the window
		// we found around, and check if it still is here. This is not really kosher, since window handles are recycled,
		// but in practice it should work.
		if (m_hWndThread != NULL && !IsWindow(m_hWndThread)) {
			m_hWndThread = NULL;
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::WaitForThread() [Thread window detected gone]"), GetCurrentThreadId()).LogEvent(1);
		}

		if (m_ThreadDiff.empty() && m_SetOfDiffHwnd.empty() && m_hWndThread == NULL) {
			break;
		}
		Sleep(500);
	}
}
//
//  Do a variety of tests to return an indication if we think that installing
//  psapi.dll will imporove our chances of sucessfully identifying child
//  processes.
//
//  Basically, we look at the platform version, and then if the entry is missing
//  we recommend installation by returning non-zero value.
//
//  If we get unexpected errors below, we do not recommend installing psapi.dll,
//  as we are probably to far out on a limb anyway, either in unexpected new os-
//  versions, or stuff simply to old to imagine.
//
bool
CChildProc::NeedPsapi() {
	return false;
}
//
//  Load all the necesary function pointers. We do it this way, since we're not
//  always sure that the target OS has the requisite entry-points, and if tid doesn't
//  and we link against a library symbol, the program will fail to load.
//
void
CChildProc::InitFunctionPointers() {
	m_hPSAPI = NULL;
	pfEnumProcesses = NULL;
	pfCreateToolhelp32Snapshot = NULL;

	if (m_hKernel32 = GetModuleHandle(_T("kernel32.dll"))) {
#pragma warning(push)
#pragma warning(disable:4191)
		if (pfCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)GetProcAddress(m_hKernel32, "CreateToolhelp32Snapshot")) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::InitFunctionPointers [CreateToolhelp32Snapshot detected]"), GetCurrentThreadId()).LogEvent();
			pfProcess32First = (PROCESS32FIRST)GetProcAddress(m_hKernel32, "Process32First");
			pfProcess32Next = (PROCESS32NEXT)GetProcAddress(m_hKernel32, "Process32Next");
			pfThread32First = (THREAD32FIRST)GetProcAddress(m_hKernel32, "Thread32First");
			pfThread32Next = (THREAD32NEXT)GetProcAddress(m_hKernel32, "Thread32Next");
			pfModule32First = (MODULE32FIRST)GetProcAddress(m_hKernel32, "Module32First");
			pfModule32Next = (MODULE32NEXT)GetProcAddress(m_hKernel32, "Module32Next");
		}
#pragma warning(pop)
	}
	if (!pfCreateToolhelp32Snapshot) {
		if (m_hPSAPI = LoadLibrary(_T("psapi.dll"))) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::InitFunctionPointers [psapi.dll loaded]"), GetCurrentThreadId()).LogEvent();
#pragma warning(push)
#pragma warning(disable:4191)
			pfEnumProcesses = (ENUMPROCESSES)GetProcAddress(m_hPSAPI, "EnumProcesses");
#pragma warning(pop)
		}
	}
}
//
//  Return a pointer to a table of process identifiers, and the number of valid
//  identifiers in the table. The returned pointer must be delete'd.
//
bool
CChildProc::NtEnumProcesses() {
	m_ciProcTable = 0;
	if (!m_hPSAPI || !pfEnumProcesses) return false;

	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::NtEnumProcesses [starting]"), GetCurrentThreadId()).LogEvent();
	// This is kind of complicated, due the stupidity of PS EnumProcesses. It will
	// not tell us how large a table it requires, so we need to try until we get
	// all.
	DWORD ciTableSize = 512;            // This seems like a good start. Probably large enough!
	do {
		ciTableSize += ciTableSize;     // Try double previous
		m_pdwProcTable = auto_ptr<DWORD>(new DWORD[ciTableSize]);

		ASSPTR(m_pdwProcTable.get());

		DWORD cbTableSize;
		if (!pfEnumProcesses(m_pdwProcTable.get(), ciTableSize * sizeof DWORD, &cbTableSize)) {
			m_ciProcTable = 0;
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::NtEnumProcesses [failed]"), GetCurrentThreadId()).LogEvent();
			return false;
		}
		m_ciProcTable = cbTableSize / sizeof DWORD;
	} while (ciTableSize == m_ciProcTable);
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::NtEnumProcesses [succeeded]"), GetCurrentThreadId()).LogEvent();
	return true;
}
//
//  Take an incremental snapshop, saving the process IDs of new child processes.
/// \brief Find new children of m_dwPProcesId that are not already procSetOld
/// \param fIgnoreParent (default false), if true do not add processes that are direct children of m_dwPProcessId
void
CChildProc::AddNewChildProcesses(dwSetT& procSetOld, dwSetT& procSetNew, bool fIgnoreParent) {
	// OS-dependent code here, but the strategy is not to try to look at OS-versions,
	// but instead try different possibilities, thus handling unkonwn os-version reports
	// more gracefully and in general being more general - if such a word can be used
	// for this kind of stupid stuff.

	// In general - we fail silently and gracefully in all cases below without visible
	// signs of distress - memory allocation excepted.

	// We like to use the toolhelp first - mostly because it is newer and more
	// frequently available.
	if (pfCreateToolhelp32Snapshot) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [using Toolhelp32 - GetCurrentProcessId()]"), GetCurrentProcessId()).LogEvent();
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [m_dwPProcessId]"), m_dwPProcessId).LogEvent();

		if (CMessage::LogLevel() >= 3) {
			dwSetT::iterator it;
			for (it = procSetNew.begin(); it != procSetNew.end(); it++) {
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [procSetNew[x]]"), *it).LogEvent(3);
			}
		}

		HANDLE hSnapshot = pfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 stProcessEntry;
		stProcessEntry.dwSize = sizeof stProcessEntry;

		if (pfProcess32First(hSnapshot, &stProcessEntry)) {
			do {
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [stProcessEntry.th32ProcessID]"), stProcessEntry.th32ProcessID).LogEvent(3);
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [stProcessEntry.th32ParentProcessID]"), stProcessEntry.th32ParentProcessID).LogEvent(3);

				// Iterate through all processes in the system, adding new child processes to m_dwPProcessId
				// Add as new IF (this process is child of m_dwPProcessID AND fIgnoreParent == false) OR this process parent is already part of the new set.
				// For each process, if fIgnoreParent is true, we add processes that have a parent that is already in the "new" set.
				// if this has the given id as it's parent we found one, or this items
				// parent is one of the processes already in the set... That way we can
				// find children of children as well.
				if ((!fIgnoreParent && (stProcessEntry.th32ParentProcessID == m_dwPProcessId)) ||
					// .. or if this processes parent is already marked in the 'new' diff set from the mark. This is intended to be interpreted
					// as the process being a child of a child - since processes in the 'new' set are supposed to be children of m_dwPProcessId.
					(procSetNew.find(stProcessEntry.th32ParentProcessID) != procSetNew.end()) ||
					// .. or we're in the mark mode, were we register _all_ current processes, so as not to get confused later if it turns
					// out one of the existing processes has a now-defunct parent process id that happens to get re-used as our firstly launched
					// application, i.e. notepad, and we then suddenly start thinking that these old processes are actually children of our
					// shiny new notepad. And yes, this complete whole thing is in major need of rewriting. The whole strategy needs re-evaluation,
					// process id's are not a good thing to use, or if we do, the code really, really needs a total reengineering session.
					(m_dwPProcessId == 0)) {
					if (procSetOld.find(stProcessEntry.th32ProcessID) == procSetOld.end()) {
						// This is a bit of a kludge, we should figure out why we even can get here with
						// ourselves.
						if (stProcessEntry.th32ProcessID != GetCurrentProcessId()) {
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [procSetNew.insert]"), stProcessEntry.th32ProcessID).LogEvent(3);
							procSetNew.insert(stProcessEntry.th32ProcessID);
						}
						else {
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [NOT procSetNew.insert (ourselves)]"), stProcessEntry.th32ProcessID).LogEvent(3);
						}
					}
				}
			} while (pfProcess32Next(hSnapshot, &stProcessEntry));
		}
		CloseHandle(hSnapshot);
		return;
	}

	// Next let's try the NT-stuff - dependent on PSAPI.DLL, which the install
	// may, or may not, have installed on the system.
	// Try to get the address of the native API-function
#pragma warning(push)
#pragma warning(disable:4191)
	PROCNTQSIP pfNtQueryInformationProcess = (PROCNTQSIP)GetProcAddress(
		GetModuleHandle(_T("ntdll.dll")),
		"NtQueryInformationProcess");
#pragma warning(pop)

	if (pfNtQueryInformationProcess != NULL) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [using psapi.dll]"), GetCurrentProcessId()).LogEvent();
		if (NtEnumProcesses()) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [NetEnumProcesses() > 0]"), GetCurrentThreadId()).LogEvent(2);
			for (DWORD i = 0; i < m_ciProcTable; i++) {
				HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, m_pdwProcTable.get()[i]);
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [OpenProcess()]"), m_pdwProcTable.get()[i]).LogEvent(2);
				if (hProc) {
					CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [hProc != NULL]"), GetCurrentThreadId()).LogEvent(2);
					PROCESS_BASIC_INFORMATION pbi;
					ZeroMemory(&pbi, sizeof pbi);

					LONG lStatus = pfNtQueryInformationProcess(hProc, ProcessBasicInformation, (PVOID)&pbi, sizeof PROCESS_BASIC_INFORMATION, NULL);
					CloseHandle(hProc);
					if (lStatus == 0) {
						CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [lStatus == 0]"), GetCurrentThreadId()).LogEvent(2);
						// this process has the given id as its parent, lets add it!
						if ((!fIgnoreParent && pbi.InheritedFromUniqueProcessId == m_dwPProcessId) ||
							(procSetNew.find(pbi.InheritedFromUniqueProcessId) != procSetNew.end())) {
							if (procSetOld.find(pbi.UniqueProcessId) == procSetOld.end()) {
								CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewChildProcesses [Adding process]"), GetCurrentProcessId()).LogEvent(2);
								procSetNew.insert(pbi.UniqueProcessId);
							}
						}
					}
				}
			}
		}
	}
}
//
//  Scan a given process for threads, and add those not found in the Old set to the New
//
void
CChildProc::FindNewThreadsOfProc(dwSetT& threadOld, dwSetT& threadNew, dwSetT& procSet) {
	if (!pfCreateToolhelp32Snapshot) return;

	HANDLE hSnapshot = pfCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te32;
	te32.dwSize = sizeof te32;

	DWORD dwLogLevel = CMessage::LogLevel(); // We're having a performance issue here, so let's optimize a bit
	if (pfThread32First(hSnapshot, &te32)) {
		do {
			// This is just to speed up this a bit, we're having a performance issue here...
			DWORD dwOwnerProcessID = te32.th32OwnerProcessID;
			DWORD dwThreadID = te32.th32ThreadID;
			if (dwLogLevel >= 3) {
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::FindNewThreadsOfProc [Checking a candidate thread]"), dwThreadID).LogEvent(4);
			}

			// If this thread is owned by a candidate process
			if (procSet.find(dwOwnerProcessID) != procSet.end()) {
				// If the thread is not already known in the old thread set, add it to the new
				if (threadOld.find(dwThreadID) == threadOld.end()) {
					CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::FindNewThreadsOfProc [threadNew.insert]"), dwThreadID).LogEvent(2);
					threadNew.insert(dwThreadID);
				}
			}
		} while (pfThread32Next(hSnapshot, &te32));
	}
	CloseHandle(hSnapshot);
}
//
//  Find threads belonging to likely processes, where likely is determined
//  by the path to the executable we're about to launch or have launched.
//  We compare with a current set, and add the new.
/// \param hWndForeground Set to non-NULL if we have detected a new foreground window to use as the base.
//
void
CChildProc::AddNewThreads(dwSetT& threadOld, dwSetT& threadNew, HWND hWndForeground) {
	threadNew.clear();           // Empty the set - it's always the current relation to old that matters.

	// First strategy is to try to find the new foreground window, and from that identify
	// the process and thread.
	if ((m_hWndThread = hWndForeground) != NULL) {
		threadOld.clear();				// If we detect a foreground change - always clear the old.
		DWORD dwProcId, dwThreadId = GetWindowThreadProcessId(m_hWndThread, &dwProcId);
		threadNew.insert(dwThreadId);

		// Lot's of debug messages here...
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewThreads() [Found new foreground thread]"), GetCurrentThreadId()).LogEvent(2);
		_TCHAR sz[1024];
		GetWindowText(m_hWndThread, sz, sizeof sz / sizeof sz[0]);
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, sz, GetCurrentThreadId()).LogEvent(2);
		return;
	}

	// Now for the next strategy, look for likely processes and threads. But the above works
	// better in many cases. We only get here if the above could not detect any foreground
	// window change.

	// Check if we have the entry-points (we assume that if we have the
	// the main, we have them all...)
	if (!pfCreateToolhelp32Snapshot) return;

	dwSetT procSet;                     // The set of process candidates
	HANDLE hSnapshot = pfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof pe32;
	if (pfProcess32First(hSnapshot, &pe32)) {
		do {
			// If this process has the same executable as the expected app...
			if (_tcsicmp(m_szExecFile.c_str(), pe32.szExeFile) == 0) {
				procSet.insert(pe32.th32ProcessID);
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewThreads(1) [Found new process with the expected executable]"), pe32.th32ProcessID).LogEvent(2);
				CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewThreads(2) [Found new module with the expected executable]"), m_szExecFile.c_str()).LogEvent(2);
			}
			else {
				HANDLE hSnapshot = pfCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
				MODULEENTRY32 me32;
				me32.dwSize = sizeof me32;
				if (pfModule32First(hSnapshot, &me32)) {
					do {
						// if this module has the same executable as the expected app
						if (_tcsicmp(m_szExecFile.c_str(), me32.szExePath) == 0) {
							procSet.insert(pe32.th32ProcessID);
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewThreads(3) [Found new process with the expected executable]"), pe32.th32ProcessID).LogEvent(2);
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewThreads(4) [Found new module with the expected executable]"), m_szExecFile.c_str()).LogEvent(2);
						}
					} while (pfModule32Next(hSnapshot, &me32));
				}
				CloseHandle(hSnapshot);
			}
		} while (pfProcess32Next(hSnapshot, &pe32));
		FindNewThreadsOfProc(threadOld, threadNew, procSet);
	}
	CloseHandle(hSnapshot);
}
//
//  Take a snapshot of the current threads, and check if any threads
//  from the list of 'known' threads are still running.
//
//  return 'true' if all threads are gone.
//
bool
CChildProc::CheckAllThreads(dwSetT& threads) {
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::CheckAllThreads() [GetCurrentThreadId()]"), GetCurrentThreadId()).LogEvent(2);
	if (!pfCreateToolhelp32Snapshot) return true;

	HANDLE hSnapshot = pfCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te32;
	te32.dwSize = sizeof te32;
	bool fAllGone = true;
	if (pfThread32First(hSnapshot, &te32)) {
		do {
			if (threads.find(te32.th32ThreadID) != threads.end()) {
				fAllGone = false;
				break;
			}
		} while (pfThread32Next(hSnapshot, &te32));
	}
	CloseHandle(hSnapshot);
	if (fAllGone) {
		threads.clear();
	}
	return fAllGone;
}

/// \brief Enumerate and add windows to new that are not in old
void CChildProc::AddNewWindows(hwndSetT &hwndOld, hwndSetT &hwndNew) {
	m_SetOfSnapHwnd.clear();
	EnumWindows(EnumWindowsProc, (LPARAM)this);
	hwndSetT::iterator it;
	for (it = m_SetOfSnapHwnd.begin(); it != m_SetOfSnapHwnd.end(); it++) {
		// If we don't find it in the set of old, we add it to the new set
		if (hwndOld.find(*it) == hwndOld.end()) {
			_TCHAR sz[1024];
			GetWindowText(*it, sz, sizeof sz / sizeof sz[0]);
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::AddNewWindows() [insert()]"), sz).LogEvent(2);

			hwndNew.insert(*it);
		}
	}
}

/// \brief Check if any of the windows in the set are still around
/// \return true if no windows on the list remain
bool
CChildProc::CheckAllWindows(hwndSetT& hwnds) {
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::CheckAllWindows() [GetCurrentThreadId()]"), GetCurrentThreadId()).LogEvent(2);
	hwndSetT::iterator it = hwnds.begin();
	while (it != hwnds.end()) {
		if (IsWindowVisible(*it)) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::CheckAllWindows() [IsWindowVisible()]"), GetCurrentThreadId()).LogEvent(2);
			return false;
		}
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::CheckAllWindows() [hwnds.erase()]"), GetCurrentThreadId()).LogEvent(2);
		hwndSetT::iterator tit = it;
		it++;
		hwnds.erase(tit);
	}
	return true;
}

/// \brief Fill m_SetOfSnapHwnd with visible windows
BOOL
CChildProc::EnumWindowsProc(HWND hwnd) {
	if (IsWindowVisible(hwnd)) {
		_TCHAR sz[1024];
		GetWindowText(hwnd, sz, sizeof sz / sizeof sz[0]);
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("CChildProc::EnumWindowsProc() [GetWindowsText()]"), sz).LogEvent(2);

		m_SetOfSnapHwnd.insert(hwnd);
	}
	return TRUE;
}