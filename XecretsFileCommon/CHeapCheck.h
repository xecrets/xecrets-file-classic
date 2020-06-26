#include "stdafx.h"

//
//	Helper to detect memory leaks.
//
#ifndef	_DEBUGHEAP
#ifdef	_DEBUG
class CHeapCheck {
	size_t m_stAlloc;
	BOOL m_fLeakOk;
	LPTSTR m_szFunc;
public:
	CHeapCheck(LPTSTR szFunc = _T("[not given]"), BOOL fLeakOk = FALSE);
	~CHeapCheck();
};
#endif	_DEBUG
#endif	_DEBUGHEAP
