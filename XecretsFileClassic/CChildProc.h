#ifndef _CCHILDPROC
#define _CCHILDPROC
/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

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
----
	CChildProc.h                    Child process utilities of a more esotric kind, that really
									should be implemented in the Win32 API.

	E-mail                          YYYY-MM-DD              Reason
	support@axantum.com             2001                    Initial

*/
#include    "tlhelp32.h"

#pragma warning(disable:4786)           // debug info truncated to 255 chars
#pragma warning(disable:4284)           // -> not for UDT etc
#include <memory>
#include <set>
#include <map>
using namespace std;

#define ProcessBasicInformation 0

typedef struct {
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}   PROCESS_BASIC_INFORMATION;
//
//  Can't use import libraries as they might cause the program to fail load in
//  some operating systems.
//
//
//  Win 95/98/ME/2K(/XP?) stuff
//
typedef HANDLE(WINAPI* CREATETOOLHELP32SNAPSHOT)(DWORD, DWORD);
typedef BOOL(WINAPI* PROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* PROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* THREAD32FIRST)(HANDLE, LPTHREADENTRY32);
typedef BOOL(WINAPI* THREAD32NEXT)(HANDLE, LPTHREADENTRY32);
typedef BOOL(WINAPI* MODULE32FIRST)(HANDLE, LPMODULEENTRY32);
typedef BOOL(WINAPI* MODULE32NEXT)(HANDLE, LPMODULEENTRY32);
//
//  NT-stuff
//
typedef LONG(WINAPI* PROCNTQSIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef BOOL(WINAPI* ENUMPROCESSES)(DWORD*, DWORD, DWORD*);

typedef set<DWORD> dwSetT;
typedef set<HWND> hwndSetT;                 ///< A set of HWND

class CChildProc {
public:
	CChildProc();
	CChildProc(DWORD dwProcId, const TCHAR* szExecName); // Create the snapshot
	~CChildProc();                      // Delete the buffers etc.

	void Mark(DWORD dwProcId, const TCHAR* szExecName); // Scan for kids, adding to the list of known
	void Diff(bool fIgnoreParent = false, HWND hWndForeground = NULL); // Store differences from Mark().
	bool ProcessFound();                // If at least one child process was found
	bool ThreadFound();                 // If at least one likely new thread was found
	void WaitForInputIdle(const TCHAR* szFileName); // Wait for all processes to go input idle
	void WaitForProcess();              // Wait for all process to finish
	void WaitForProcessAndNewChildren();// Wait for all process, and periodically check for children too
	void WaitForThread();               // Wait for all threads to finish
	bool NeedPsapi();                   // Return non-zero if we need to install psapi.
private:
	HINSTANCE m_hPSAPI;
	ENUMPROCESSES pfEnumProcesses;

	HMODULE m_hKernel32;
	CREATETOOLHELP32SNAPSHOT pfCreateToolhelp32Snapshot;
	PROCESS32FIRST pfProcess32First;
	PROCESS32NEXT pfProcess32Next;
	MODULE32FIRST pfModule32First;
	MODULE32NEXT pfModule32Next;
	THREAD32FIRST pfThread32First;
	THREAD32NEXT pfThread32Next;

	axpl::ttstring m_szExecFile;        // Path to executable
	DWORD m_dwPProcessId;               // Saved parent process ID
	dwSetT m_SetOfMarkProc, m_SetOfDiffProc;
	dwSetT m_ThreadMark, m_ThreadDiff;

	hwndSetT m_SetOfMarkHwnd;           ///< The set of visible windows at 'mark'
	hwndSetT m_SetOfDiffHwnd;           ///< The set of new visible windows compared with 'mark' at 'diff'
	hwndSetT m_SetOfSnapHwnd;           ///< The last snapshot of visible windows

	HWND m_hWndThread;                  ///< Handle to window owning detected thread(s) (if any, otherwise NULL)

	auto_ptr<DWORD> m_pdwProcTable;     // Process-table used on NT
	size_t m_ciProcTable;               // Number of entries in said table

	void InitFunctionPointers();        // Init the DLL-entry-point function-pointers
	bool NtEnumProcesses();             // Get process list on NT into array, and number of entries as well.

	void AddNewChildProcesses(dwSetT& procSetOld, dwSetT& procSetNew, bool fIgnoreParent = false);
	void FindNewThreadsOfProc(dwSetT& threadOld, dwSetT& threadNew, dwSetT& procSet);
	void AddNewThreads(dwSetT& threadOld, dwSetT& threadNew, HWND hWndForeground);
	bool CheckAllThreads(dwSetT& threads);
	void AddNewWindows(hwndSetT& hwndOld, hwndSetT& hwndNew);
	bool CheckAllWindows(hwndSetT& hwnds);

	static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
		return ((CChildProc*)lParam)->EnumWindowsProc(hwnd);
	}
	BOOL EnumWindowsProc(HWND hwnd);
};
#endif  _CCHILDPROC