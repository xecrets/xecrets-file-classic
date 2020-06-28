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
	CEntropy.cpp					Entropy pool gathering and reading

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2002					Initial
*/
#include	"StdAfx.h"
#include	"CEntropy.h"
#include    "../XecretsFileCommon/CRegistry.h"
#include	<mmsystem.h>

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CEntropy.cpp"
//
//	Define SLOWSAFE to guard against bias for 1 or 0 in the
//	oscillating random bit generator.
//
// #define	SLOWSAFE

/// \brief Check to see if we should be using our own entropy pool, or Windows Crypto API
///
/// In the initial design goal was a requirement not to be dependent on the Windows Crypto API
/// random number generator. At that time it was new, and it was not quite clear how users would
/// react to such a use. At this time, 2006, there has been no weaknesses spotted and it seems
/// reasonable to use the Crypto API instead of this homegrown. Also, it's been a FAQ about why
/// Xecrets File consumes memory and processor time even when not idle, and that's caused more grief
/// than any possible kudos received due to the careful design of the entropy generator. So, as
/// a first step, we introduce a new default behavior which is to check for a new registry value,
/// and if it says TRUE we revert back to the old behavior, otherwise we shunt all the entropy
/// gathering etc, and just use the Windows API.
///
/// In the code we use the member variable to determine the state, since we could get into trouble
/// if the state in the registry was changed at an unfortunate time. It's ok to require a restart of
/// the process to change the entropy mode.
/// \return true if we should be using the old entropy gathering daemon etc.
bool
CEntropy::UseEntropyPool() {
	if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValUseEntropyPool).GetDword(FALSE) ||
		CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValUseEntropyPool).GetDword(FALSE)) {
		return true;
	}
	return false;
}

//
//
//  Constructor - load from szRegKey and szRegSubKey if given.
//
//  If the key does not exist, we create one.
//
//  hKey - starting point - probably HKEY_CURRENT_USER...
//
//	We also start the flipper and the gatherer threads in suspended state.
//	These are kick-started as requested separately.
//
CEntropy::CEntropy(HKEY hKey, LPCTSTR szRegSubKey) {
	m_bUseEntropyPool = UseEntropyPool();

	m_pEntropyPool = new BYTE[ENTROPY_POOL_SIZE];
	ASSPTR(m_pEntropyPool);

	m_iReadIndex = m_iWriteIndex = 0;

	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		ASSAPI(CryptAcquireContext(&m_hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
		return;
	}

	CAssert(hKey != NULL).App(ERR_ARGUMENT, _T("CEntropy::CEntropy")).Throw();
	CAssert(szRegSubKey != NULL).App(ERR_ARGUMENT, _T("CEntropy::CEntropy")).Throw();

	// Squirrel away the registry key and value.
	m_hRegKey = hKey;
	size_t ccRegSubKey = _tcsclen(szRegSubKey) + 1;
	m_szRegSubKey = new TCHAR[ccRegSubKey];
	ASSPTR(m_szRegSubKey);

	(void)_tcscpy_s(m_szRegSubKey, ccRegSubKey, szRegSubKey);

	m_fStopFlip = TRUE;
	m_lStopAll = TRUE;
	m_lWantedBits = 0;
}
//
//  Stop timers etc - Do *not* save - if that must be done, do it with Save()
//
CEntropy::~CEntropy() {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		ASSAPI(CryptReleaseContext(m_hCryptProv, 0));
		return;
	}
	Stop();
}
//
//	Start collecting entropy
//
CEntropy&
CEntropy::Start() {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		return *this;
	}

	// If already started - do nothing.
	if (!InterlockedExchange((LPLONG)&m_lStopAll, FALSE)) return *this;

	CMessage().Wrap(0).AppMsg(INF_ENTROPY_START).LogEvent(2);

	DWORD dwThreadId;

	// Create the flipper thread
	m_hFlipperEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CAssert(m_hFlipperEvent != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateEvent(m_hFlipperEvent)]")).Throw();
	m_hFlipperThread = CreateThread(NULL, 0, StaticFlipperThread, this, 0, &dwThreadId);
	CAssert(m_hFlipperThread != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateThread(m_hFlipperThread)]")).Throw();
	CAssert(SetThreadPriority(m_hFlipperThread, THREAD_PRIORITY_LOWEST)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [SetThreadPriority(m_hFlipperThread)]")).Throw();

	// Create the gatherer thread
	m_hGatherEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CAssert(m_hGatherEvent != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateEvent(m_hGatherEvent)]")).Throw();
	m_hGatherThread = CreateThread(NULL, 0, StaticGatherThread, this, 0, &dwThreadId);
	CAssert(m_hGatherThread != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateThread(m_hGatherThread)]")).Throw();
	CAssert(SetThreadPriority(m_hGatherThread, THREAD_PRIORITY_BELOW_NORMAL)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [SetThreadPriority(m_hGatherThread)]")).Throw();

	// Create the User Entropy thread
	m_hUserEntropyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CAssert(m_hUserEntropyEvent != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateEvent(m_hUserEntropyEvent)]")).Throw();
	m_hUserEntropyThread = CreateThread(NULL, 0, StaticUserEntropyThread, this, 0, &dwThreadId);
	CAssert(m_hUserEntropyThread != NULL).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [CreateThread(m_hUserEntropyThread)]")).Throw();
	// See [BUG 951378], modified to lower priority to reduce impact on system performance.
	CAssert(SetThreadPriority(m_hUserEntropyThread, THREAD_PRIORITY_BELOW_NORMAL)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [SetThreadPriority(m_hUserEntropyThread)]")).Throw();

	GatherBits(ENTROPY_POOL_SIZE << 3);		// Request a new, filled, entropy pool
	return *this;
}
//
//	Stop collecting entropy
//
CEntropy&
CEntropy::Stop() {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		return *this;
	}

	// If already stopped - do nothing
	if (InterlockedExchange((LPLONG)&m_lStopAll, TRUE)) return *this;

	CMessage().Wrap(0).AppMsg(INF_ENTROPY_STOP).LogEvent(2);

	// Stop the Gatherer thread...
	if (m_hGatherThread != NULL) {
		CAssert(SetEvent(m_hGatherEvent)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [SetEvent(m_hGatherEvent)]")).Throw();

		if (WaitForSingleObject(m_hGatherThread, 1000) != WAIT_OBJECT_0) {
			CMessage().Wrap(0).AppMsg(WRN_GATHER_THREAD).LogEvent();
		}
		CAssert(CloseHandle(m_hGatherThread)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [CloseHandle(m_hGatherThread)]")).Throw();
		m_hGatherThread = NULL;
	}

	// ...and stop the Flipper thread...
	if (m_hFlipperThread != NULL) {
		m_fStopFlip = TRUE;		// Stop the flipping loop, making it check the event.
		CAssert(SetEvent(m_hFlipperEvent)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [SetEvent(m_hFlipperEvent)]")).Throw();

		if (WaitForSingleObject(m_hFlipperThread, 1000) != WAIT_OBJECT_0) {
			CMessage().Wrap(0).AppMsg(WRN_FLIPPER_THREAD).LogEvent();
		}
		CAssert(CloseHandle(m_hFlipperThread)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [CloseHandle(m_hFlipperThread)]")).Throw();
		m_hFlipperThread = NULL;
	}

	// ...and stop the User Entropy Thread as well
	if (m_hUserEntropyThread != NULL) {
		CAssert(SetEvent(m_hUserEntropyEvent)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [SetEvent(m_hUserEntropyEvent)]")).Throw();

		if (WaitForSingleObject(m_hUserEntropyThread, 1000) != WAIT_OBJECT_0) {
			CMessage().Wrap(0).AppMsg(WRN_USERENTROPY_THREAD).LogEvent();
		}
		CAssert(CloseHandle(m_hUserEntropyThread)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Stop [CloseHandle(m_hUserEntropyThread)]")).Throw();
		m_hUserEntropyThread = NULL;
	}
	return *this;
}
//
//	Load half of the entropy pool from the registry as starter.
//
CEntropy&
CEntropy::Load() {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		return *this;
	}

	DWORD dwRegPoolSize = ENTROPY_POOL_SIZE / 2;
	DWORD dwType = REG_BINARY;
	if (OpenRegSubKey()) {
		LONG dwReturn = RegQueryValueEx(m_hRegSubKey, szRegValueEntropyPool, NULL, &dwType, m_pEntropyPool, &dwRegPoolSize);
		if (dwReturn != ERROR_SUCCESS) {
			SetLastError(dwReturn);
			CAssert(dwReturn == ERROR_FILE_NOT_FOUND).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Start [ReqQueryValueEx]")).Throw();
		}
		CMessage().Wrap(0).AppMsg(INF_LOADED_ENTROPY).LogEvent();
	}
	return *this;
}
//
//  Save half of the entropy to the registry.
//
CEntropy&
CEntropy::Save() {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		return *this;
	}

	if (OpenRegSubKey()) {
		CAssert(RegSetValueEx(m_hRegSubKey, szRegValueEntropyPool, 0, REG_BINARY, m_pEntropyPool, ENTROPY_POOL_SIZE / 2) == ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("RegSetValueEx() [CEntropy::Save()]")).Throw();
		CMessage().Wrap(0).AppMsg(INF_SAVED_ENTROPY).LogEvent(4);
	}
	return *this;
}
//
//  Read and return the number of bytes of entropy requested for.
//
//  We conservatively estimate 2 bits of entropy/byte in the pool,
//  so we read 4*the number of bytes requested, and condense via
//  XOR into the requested length.
//
//  Return the pointer given - makes the usagage easier...
//
//  There is no checking or handling of the case where more entropy
//  is requested than actually exist. We have no clue, actually... ;-)
//
BYTE*
CEntropy::Read(BYTE* aoDst, size_t stLen) {
	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		ASSAPI(CryptGenRandom(m_hCryptProv, (DWORD)stLen, (BYTE*)aoDst));
		return aoDst;
	}

	CMessage().Wrap(0).AppMsg(INF_USING_ENTROPY, (int)(stLen * 8)).LogEvent(4);
	for (size_t stExLen = stLen << 2; stExLen; stExLen--) {
		// Stricty speaking, aoDst is not initialized. Ok for entropy.
		// Nor is this truly thread-safe. Ok for entropy though.
		aoDst[stExLen % stLen] ^= m_pEntropyPool[IncPoolIndex(&m_iReadIndex)];
	}
	// We always fill the entire pool after having something read from it.
	GatherBits(ENTROPY_POOL_SIZE << 3);
	return aoDst;
}
//
//	Add entropy if we happen to get it externally...
//
void
CEntropy::Add(BYTE* aoSrc, size_t stLen) {
	while (stLen--) {
		m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= *aoSrc++;
	}

	// New behavior is to use the Windows API
	if (!m_bUseEntropyPool) {
		// This actually seeds the windows API pool
		(void)Read(m_pEntropyPool, ENTROPY_POOL_SIZE);
		return;
	}
}
//
//	Request a number of bits from the gatherer,
//	and signal it to start.
//
void
CEntropy::GatherBits(long lBits) {
	CMessage().Wrap(0).AppMsg(INF_GATHERING_ENTROPY, lBits).LogEvent(4);
	// Fill the entropy pool with bits from the gatherer too.
	// We maximize at the entropy pool size, which means that we do as
	// good as we can during activity, and then replenish the entire pool.
	lBits = InterlockedExchange((LPLONG)&m_lWantedBits, lBits) + lBits;
	lBits = (lBits > (ENTROPY_POOL_SIZE << 3)) ? (ENTROPY_POOL_SIZE << 3) : lBits;
	(void)InterlockedExchange((LPLONG)&m_lWantedBits, lBits);

	m_fStopFlip = FALSE;
	CAssert(SetEvent(m_hFlipperEvent)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::CEntropy [SetEvent(m_hFlipperEvent)]")).Throw();
	CAssert(SetEvent(m_hGatherEvent)).Sys(MSG_SYSTEM_CALL, _T("CEntropy::CEntropy [SetEvent(m_hGatherEvent)]")).Throw();
}
//
//	Call the counter function in the instantiated class, using the this parameter
//	passed as parameter.
//
DWORD WINAPI
CEntropy::StaticFlipperThread(LPVOID lpParameter) {
	CAssert(lpParameter != NULL).App(ERR_ARGUMENT, _T("CEntropy::StaticFlipperThread")).Throw();
	((CEntropy*)lpParameter)->FlipperThread();
	return 0;
}
//
//	A fast bit-flipper... The low bit does the
//	flipping, autoincrement of an int should be
//	the fastest availabe operation.
//
//	Basically we're creating an almost-firmware
//	oscillator at frequency of several, probably 10's
//	or even 100's of MHz, depending on CPU. It
//	should generate decent quality randomness, although
//	it does depend on activity in the system.
//
//	A Pentium III 700MHz with Windows 2000 Professional
//	seems to get about 100MHz+ out of it.
//
void CEntropy::FlipperThread() {
	//
	//	The reason for not using an event object in the
	//	flipping loop, is we want to have that
	//	bit flipping at as high a frequency as is possible.
	//
	do {
		while (!m_fStopFlip) m_uiBit++;
		WaitForSingleObject(m_hFlipperEvent, INFINITE);
	} while (!m_lStopAll);
}
//
//	call the gathering function in the instantiated class, using the this
//	passed as parameter.
//
DWORD WINAPI
CEntropy::StaticGatherThread(LPVOID lpParameter) {
	CAssert(lpParameter != NULL).App(ERR_ARGUMENT, _T("CEntropy::StaticCounterThread")).Throw();

	((CEntropy*)lpParameter)->GatherThread();
	return 0;
}
//
//	Bit oscillator-based entropy generation.
//
//	Actually gather entropy from a free running flipping bit.
//
//	#ifdef SLOWSAFE:
//
//	We take two samples/bit, to even out probabilities:
//	if probability of a one is p, the a zero has prob 1-p.
//	Thus:	00	-> (1-p)(1-p)
//			01	-> (1-p)p
//			10	-> p(1-p)
//			11	-> pp
//
//	That bit 'stolen' from Tom St Denis, libtomcrypt.
//
//	In this case, each double bit takes 2ms.
//	The probability is about 1/2 that it is 01 or 10,
//	thus the timing is about 4ms/bit.
//
//	#else we just take the bit, but guard against a silent
//	oscillator.
//
//	We generate 8*ENTROPY_POOL_SIZE bits. If size is 256,
//	then we get 8*256*4 ms to fill the entropy pool, or about
//	8 seconds/2 seconds depending on SLOWSAFE.
//
//	Also note that altogether we still only take
//	2 bits/byte in the pool when we read it, so it is relatively
//	conservative still.
//
//	A typical system timer resolution in Win32 is 10ms - way too
//	low, so we use multimedia timers instead which offer down to
//	1ms resolution. These are supported on 95/98/ME/NT/2K/XP.
//
void
CEntropy::GatherThread() {
	// Get timer caps, attempt to go down to 1ms if possible, otherwise as good as it gets.
	TIMECAPS tc; UINT cbtc = sizeof tc;
	CAssert(timeGetDevCaps(&tc, cbtc) == TIMERR_NOERROR).App(ERR_MMTIMER, _T("CEntropy::Gather [timeGetDevCaps]")).Throw();
	DWORD dwResolution = min(max(1, tc.wPeriodMin), tc.wPeriodMax);
	CAssert(timeBeginPeriod(dwResolution) == TIMERR_NOERROR).App(ERR_MMTIMER, _T("CEntropy::Gather [timeBeginPeriod]")).Throw();

	// We use event pulsing in the timer, so let's get an event object.
	CHandle hTick = CreateEvent(NULL, FALSE, FALSE, NULL);
	CAssert(hTick.IsValid()).Sys(MSG_SYSTEM_CALL, _T("CEntropy::Gather [CreateEvent]")).Throw();

	// Start the timer ticking...
	UINT uTimerId;
	CAssert(uTimerId = timeSetEvent(dwResolution, dwResolution, (LPTIMECALLBACK)(HANDLE)hTick, 0, TIME_PERIODIC | TIME_CALLBACK_EVENT_PULSE)).App(ERR_MMTIMER, _T("CEntropy::Gather [timeSetEvent]")).Throw();

	unsigned int uiRunFlipSum = 0, uiN = 0;
	BOOL fWasStarted = FALSE;
	do {
		// get the requested number of bits, communicated by m_lWantedBits.
		int iBits = 0;
		static BYTE oEntropy = 0;
		int iA;
		while (!m_lStopAll && (InterlockedDecrement((LPLONG)&m_lWantedBits) >= 0)) {
			int cMax = 64;	// Probability, when ok, of cMax==0 is <= 2**(-cMax).
			unsigned int uiLastFlip;
			fWasStarted = TRUE;
#ifdef	SLOWSAFE
			int iB;
			do {
				// Safety-first, wait a maximum of 10ms
				(void)WaitForSingleObject(hTick, 10);
				iA = m_uiBit & 1;
				(void)WaitForSingleObject(hTick, 10);
				iB = m_uiBit & 1;
			} while (iA == iB && --cMax && !m_lStopAll);
#else
			// Do not accept bits produced at below 1MHz apparent oscillator.
			// Either Flipper is dead, the poor dolphin, or the system is too
			// slow or loaded to generate decent entropy this way.
			do {
				uiLastFlip = m_uiBit;
				// Safety-first, wait a maximum of 10ms
				(void)WaitForSingleObject(hTick, 10);
				iA = m_uiBit & 1;
				//
				// Keep a running sum of the approximate last 100 numbers.
				// Under normal cirumstances, where the poll frequency is
				// about 1ms, this means we can correctly handle bit
				// oscillations on the order of 40 GHz, representing a CPU
				// probably on the order of 200 - 400 GHz.
				// In the worst case we only handle CPU's on the order of
				// 20 - 40GHz (should arrive ca. 2007.) But nothing really
				// bad happens, and with that kind of machine - why would
				// we not get our 1 ms resolution???
				//
				if (uiN == 100) {
					uiRunFlipSum -= uiRunFlipSum / 100;
				}
				else {
					uiN++;
				}
				uiRunFlipSum += m_uiBit - uiLastFlip;
			} while (((m_uiBit - uiLastFlip) / dwResolution < 1000L) && --cMax && !m_lStopAll);
#endif
			// At this point we do not do anything about low-entropy bits, it happens
			// sometimes when the system is very loaded, but thre is not much to do,
			// and there is never any hurt in using what we get.
			if (!cMax) {
				;	// Here we could warn, try something else, abort or whatever.
			}
			iA ^= GetTimeStampBit();		// Use a bit from cycle counter too.
			oEntropy <<= 1;
			oEntropy |= iA;
			if ((++iBits & 7) == 0) {
				m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= oEntropy;
			}
		}
		// If it *was* zero, it became -1, so adjust for that fact.
		InterlockedIncrement((LPLONG)&m_lWantedBits);
		// If a non-multiple of 8 bits was requested.
		if (iBits & 7) {
			// If we get into conflict with the other entropy gathering by
			// simultaneous access to the pool, that is ok. We do want
			// unpredictability ;-). Nothing bad happens, the likelyhood is
			// extremely low, and the overhead of critical sections are
			// just too much here.
			m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= oEntropy;
		}
		oEntropy = 0;
		m_fStopFlip = TRUE;
		(void)WaitForSingleObject(m_hGatherEvent, INFINITE);
	} while (!m_lStopAll);
	//
	// Currently no running average speed in slowsafe mode
	//
#ifndef	SLOWSAFE
	if (fWasStarted) {
		CMessage().Wrap(0).AppMsg(MSG_OSCILLATOR, ((uiRunFlipSum / uiN) / dwResolution) / 1000L).LogEvent();
	}
#endif
	CAssert(timeKillEvent(uTimerId) == TIMERR_NOERROR).App(ERR_MMTIMER, _T("CEntropy::Gather [timeKillEvent]")).Throw();
	CAssert(timeEndPeriod(dwResolution) == TIMERR_NOERROR).App(ERR_MMTIMER, _T("CEntropy::Gather [timeEndPeriod]")).Throw();
	hTick.Close();
}

DWORD WINAPI
CEntropy::StaticUserEntropyThread(LPVOID lpParameter) {
	CAssert(lpParameter != NULL).App(ERR_ARGUMENT, _T("CEntropy::StaticUserEntropyThread")).Throw();

	((CEntropy*)lpParameter)->UserEntropyThread();
	return 0;
}
//
//	This thread waits for a termination event, with a variable timeout.
//	At each timeout, it checks if something has happened with the windows
//	or the mouse - if so, it collects a hashed byte of that state and adds
//	it to the entropy pool.
//
//	If the system is inactive, the timeout is stepwise increase, up to a
//	coded maximum.
//
//	When the termination event is fired, it just quietly exits.
//
void
CEntropy::UserEntropyThread() {
	// It appears that 20 is not a good value. See [BUG 951378]
	const int iSamplingFreq = 41;       // Milliseconds >20ms, and a prime to boot!

	BYTE oLastPointHash = 0, oLastWindowsHash = 0;
	unsigned int utTimeToNext = iSamplingFreq;

	do {
		POINT stNewPoint;
		BYTE oNewPointHash, oNewWindowsHash;

		GetCursorPos(&stNewPoint);
		oNewPointHash = ByteSumHash(&stNewPoint, sizeof stNewPoint);

		oNewWindowsHash = WindowsStateHash();

		// Assume all quiet.. Increase idle-time.
		utTimeToNext += utTimeToNext;		// If all quiet - double waiting time.
		utTimeToNext = Min(utTimeToNext, 1000 * 10);	// But not longer than 10 seconds...

		//	Add to entropy pool if new value, and also reset timer to frequent value if so.
		if (oNewWindowsHash != oLastWindowsHash) {
			m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= oLastWindowsHash = oNewWindowsHash;
			utTimeToNext = iSamplingFreq;
#ifndef _DEBUGPLUS
			HEAP_CHECK_BEGIN(_T("UserEntropyThread [Windows]"), FALSE);
			CMessage().Wrap(0).AppMsg(INF_WINDOWS_ENTROPY).LogEvent(5);
			HEAP_CHECK_END
#endif
		}
		if (oNewPointHash != oLastPointHash) {
			m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= oLastPointHash = oNewPointHash;
			utTimeToNext = iSamplingFreq;			// Something happend - back to normal sampling freq
#ifndef _DEBUGPLUS
			HEAP_CHECK_BEGIN(_T("UserEntropyThread [Mouse]"), FALSE);
			CMessage().Wrap(0).AppMsg(INF_MOUSE_ENTROPY).LogEvent(5);
			HEAP_CHECK_END
#endif
		}
		// Get a time-stamp byte too
		m_pEntropyPool[IncPoolIndex(&m_iWriteIndex)] ^= GetTimeStampByte();
	} while (WaitForSingleObject(m_hUserEntropyEvent, utTimeToNext) == WAIT_TIMEOUT);
}
//
//	Called by EnumWindows below, gets the state of one window
//	and adds it to a 'hash'.
//
BOOL CALLBACK
CEntropy::WindowsStateHashEnumProc(HWND hwnd, LPARAM lParam) {
	RECT stRect;
	GetWindowRect(hwnd, &stRect);
	*(BYTE*)lParam += ByteSumHash(&stRect, sizeof stRect);
	return TRUE;
}
//
//	Take all top-level window states and hash their screen coordinates
//	together, providing at least one bit of entropy when changed.
//
BYTE
CEntropy::WindowsStateHash() {
	BYTE oHash = 0;
	EnumWindows(WindowsStateHashEnumProc, (LPARAM)&oHash);
	return oHash;
}
//
BYTE
CEntropy::ByteSumHash(void* pvBuf, int iSiz) {
	register int iHash = 0;
	for (register int i = 0; i < iSiz; i++) {
		iHash += ((BYTE*)pvBuf)[i];
	}
	return (BYTE)iHash;
}
//
//	Increment a PoolIndex, return the old value.
//
//	The idea is to read and write bytes in the pool
//	spread out over the volatile and persistent part
//	in a deterministic and simple way.
//
//	We keep track of separate read and write indices.
//	No check if the read index runs 'ahead'.
//
int
CEntropy::IncPoolIndex(int* pIndex) {
	//	We are multithreaded, and no critical section here, so
	//	guard with an extra modulo...
	int iOldIndex = (*pIndex)++ % ENTROPY_POOL_SIZE;
	(*pIndex) %= ENTROPY_POOL_SIZE;
	// Odd numbers start at the top, i.e. volatile half.
	// Even at the bottom, i.e. persistent half.
	if (iOldIndex & 1) {
		return ENTROPY_POOL_SIZE - iOldIndex;
	}
	else {
		return iOldIndex;
	}
}
//
//	Attempt to open the registry sub-key. Ok to try even if
//	already open.
//
BOOL
CEntropy::OpenRegSubKey() {
	if (!m_hRegSubKey.IsValid()) {
		LONG lReturn;
		if ((lReturn = RegOpenKeyEx(m_hRegKey, m_szRegSubKey, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &m_hRegSubKey)) != ERROR_SUCCESS) {
			SetLastError(lReturn);
			CAssert(lReturn == ERROR_FILE_NOT_FOUND).Sys(MSG_SYSTEM_CALL, _T("CEntropy::OpenRegSubKey [RegOpenKeyEx]")).Throw();
			return FALSE;
		}
	}
	return TRUE;
}
//
//	Get a bit from the pentium cycle counter (RDTSC) - or zero
//	if not available.
//
BYTE
CEntropy::GetTimeStampBit() {
	SYSTEM_INFO stSysInfo;
	GetSystemInfo(&stSysInfo);
#if !defined(_WIN64)
	if (stSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL &&
		stSysInfo.dwProcessorType == PROCESSOR_INTEL_PENTIUM) {
		BYTE ubTimeStampBit;
		// This code derived from MSDN
		__asm {
			push eax; Save registers we will overwrite(eax, ebx, edx).
			push ebx
			push edx
			_emit 0x0F; The RDTSC instruction consists of these two bytes.
			_emit 0x31
			or eax, eax; Set parity bit
			setpo ubTimeStampBit; Set the byte to 1 or 0
			pop edx; Restore overwritten registers.
			pop ebx
			pop eax
		}
		return ubTimeStampBit;
	}
#endif
	return 0;
}

//
//	Get a byte from the pentium cycle counter (RDTSC) - or zero
//	if not available.
//
BYTE
CEntropy::GetTimeStampByte() {
	SYSTEM_INFO stSysInfo;
	GetSystemInfo(&stSysInfo);
#if !defined(_WIN64)
	if (stSysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL &&
		stSysInfo.dwProcessorType == PROCESSOR_INTEL_PENTIUM) {
		BYTE ubTimeStampByte;
		// This code derived from MSDN
		__asm {
			push eax; Save registers we will overwrite(eax, ebx, edx).
			push ebx
			push edx
			_emit 0x0F; The RDTSC instruction consists of these two bytes.
			_emit 0x31
			lea ebx, ubTimeStampByte
			mov[ebx], al; Get the lsb of the counter
			pop edx; Restore overwritten registers.
			pop ebx
			pop eax
		}
		return ubTimeStampByte;
	}
#endif
	return 0;
}