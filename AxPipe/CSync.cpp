/*! \file
    \brief Implementation of AxPipe::CSync thread synchronization object

    @(#) $Id$

    AxPipe - Binary Stream Framework

    Copyright (C) 2003 Svante Seleborg/Axon Data, All rights reserved.

    This program is free software; you can redistribute it and/or modify it under the terms
    of the GNU General Public License as published by the Free Software Foundation;
    either version 2 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program;
    if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
    Boston, MA 02111-1307 USA

    The author may be reached at mailto:axpipe@axondata.se and http://axpipe.sourceforge.net

    Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
    CSync.cpp                       Implementation of CSync thread synchronization object

    E-mail                          YYYY-MM-DD              Reason
    axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSync.cpp"

namespace AxPipe {
    /// \brief Create the event and also set our error pointer.
    CSync::CSync() {
        m_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        ASSAPI(m_hEvent != NULL);
    }
    
    /// \brief Close the event.
    CSync::~CSync() {
        ASSAPI(CloseHandle(m_hEvent));
    }
    
    /// \brief Wait for someone to call Signal()
    /// \param iMs Milliseconds timeout value for the wait. -1 == Infinite.
    /// \return true if the wait terminated because someone called Signal().
    bool
    CSync::Wait(int iMs) {
        DWORD dwStatus = WaitForSingleObject(m_hEvent, iMs == -1 ? INFINITE : (DWORD)iMs);
        ASSAPI(dwStatus != WAIT_FAILED);
        return dwStatus == WAIT_OBJECT_0;
    }
    
    /// \brief Send a signal to someone who's waiting with Wait().
    /// \return true if it was possible to send the signal.
    /// \see Signal()
    bool
    CSync::Signal() {
        ASSAPI(SetEvent(m_hEvent));
        return true;
    }

    CThreadSync::CThreadSync() {
        ASSAPI((m_hSemaphore = CreateSemaphore(NULL, 1, 1, NULL)) != NULL);
    }

    CThreadSync::~CThreadSync() {
        ASSAPI(CloseHandle(m_hSemaphore));
    }
    /// \brief Initiate one Work() cycle - called from outside worker thread.
    void
    CThreadSync::WorkStart() {
        WaitForSingleObject(m_hSemaphore, INFINITE);
    }

    /// \brief Signal that we've prepared for more Work() - called from outside worker thread.
    void
    CThreadSync::WorkSignal() {
        m_Work.Signal(); m_Accepted.Wait();
    }
    
    /// \brief Wait for more to be ready for Work() - this is called in the worker thread.
    void
    CThreadSync::WorkWait() {
        m_Work.Wait(); m_Accepted.Signal();
    }
    
    /// \brief End one Work() cycle - called from the worker thread.
    void
    CThreadSync::WorkEnd() {
        ReleaseSemaphore(m_hSemaphore, 1, NULL);
    }
};
