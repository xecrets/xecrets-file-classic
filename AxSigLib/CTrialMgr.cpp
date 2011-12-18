/*
    @(#) $Id$

    AxCrypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
    Server or Web Storage of Document Files.

    Copyright (C) 2004 Svante Seleborg/Axantum Software AB, All rights reserved.

    This program is free software; you can redistribute it and/or modify it under the terms
    of the GNU General Public License as published by the Free Software Foundation;
    either version 2 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program;
    if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
    Boston, MA 02111-1307 USA

    The author may be reached at mailto:axcrypt@axondata.se and http://axcrypt.sourceforge.net
----
    CTrialMgr.cpp                     Handle trial counters etc.
*/
#include "stdafx.h"
#include "CTrialMgr.h"
#include <iterator>

#include "sha.h"
#include "hex.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CTrialMgr.cpp"

/// \brief Initialize access to the trial counter storage.
CTrialMgr::CTrialMgr(const ttstring &sProgram) {
    m_sProgram = sProgram;

}

CTrialMgr::~CTrialMgr() {
}

const unsigned long TWO_SECONDS = 20000000UL;

static ttstring GetCounterPath(const ttstring &program_name, const ttstring &counter_name) {
    CryptoPP::SHA256 hash;

    ttstring source(program_name);
    source.append(counter_name);

    std::string name_hash;

    CryptoPP::StringSource(reinterpret_cast<const unsigned char *>(source.data()), source.length() * sizeof(ttstring::value_type), true,
        new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(name_hash))));
    ttstring wide_name_hash;
    std::copy(&name_hash[0], &name_hash[8], std::back_inserter(wide_name_hash));

    DWORD buffer_length = GetTempPath(0, NULL);
    TCHAR* tempPath = new TCHAR[buffer_length];
    DWORD path_length = GetTempPath(buffer_length, tempPath);
    if (path_length == 0) {
        delete[] tempPath;
        return ttstring();
    }
    
    ttstring counter_path(tempPath);
    if (counter_path[counter_path.length()-1] != L'\\') {
        counter_path.append(L"\\");
    }
    delete[] tempPath;
    counter_path.append(wide_name_hash);

    return counter_path;
}

static HANDLE OpenFile(ttstring counter_file) {
    HANDLE h = CreateFile(counter_file.c_str(), GENERIC_WRITE|GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, NULL);

    return h;
}

static HANDLE OpenAndGetTimes(const ttstring &program_name, const ttstring &counter_name, PULARGE_INTEGER create_time, PULARGE_INTEGER modify_time) 
{
    ttstring counter_path = GetCounterPath(program_name, counter_name);
    HANDLE h = OpenFile(counter_path);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD last_error = GetLastError();

        return h;
    }

    FILETIME ft_creation_time, ft_last_write_time;
    if (!GetFileTime(h, &ft_creation_time, NULL, &ft_last_write_time)) {
        BOOL isOk = CloseHandle(h);
        if (!isOk) {
            DWORD last_error = GetLastError();
        }
        return INVALID_HANDLE_VALUE;
    }

    create_time->LowPart = ft_creation_time.dwLowDateTime;
    create_time->HighPart = ft_creation_time.dwHighDateTime;
    create_time->QuadPart -= create_time->QuadPart % TWO_SECONDS;

    modify_time->LowPart = ft_last_write_time.dwLowDateTime;
    modify_time->HighPart = ft_last_write_time.dwHighDateTime;
    modify_time->QuadPart -= modify_time->QuadPart % TWO_SECONDS;

    return h;
}

int CalculateCounter(int iMax, ULARGE_INTEGER create_time, ULARGE_INTEGER modify_time) {
    if (create_time.QuadPart > modify_time.QuadPart) {
        return iMax;
    }

    ULONGLONG count = (modify_time.QuadPart - create_time.QuadPart) / TWO_SECONDS;
    if (count > iMax) {
        return iMax;
    }
    return (int)count;
}


/// \brief Get the trial counter as it is now
int CTrialMgr::Get(const ttstring &sCounterName, int iMax) {
    ULARGE_INTEGER create_time, modify_time;
    HANDLE h = OpenAndGetTimes(m_sProgram, sCounterName, &create_time, &modify_time);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }
    BOOL isOk = CloseHandle(h);
    if (!isOk) {
        DWORD last_error = GetLastError();
    }

    int current = CalculateCounter(iMax, create_time, modify_time);
    return current;
}

/// \brief Increment a trial counter by one, and return the result.
/// The result returned is maximized by the iMax parameter + 1. If 
/// iMax is < 0, there is no limit.
/// \param iMax The maximum value of the counter.
/// \return The new value, or what it would have been if allowed.
int
CTrialMgr::Increment(int iMax, const ttstring &sCounterName) {
    ULARGE_INTEGER create_time, modify_time;
    HANDLE h = OpenAndGetTimes(m_sProgram, sCounterName, &create_time, &modify_time);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    int current = CalculateCounter(iMax, create_time, modify_time);
    if (iMax >= 0 && current >= iMax) {
        BOOL isOk = CloseHandle(h);
        DWORD last_error = GetLastError();

        return iMax;
    }

    ++current;
    modify_time.QuadPart += TWO_SECONDS;

    FILETIME ft_create_time = { create_time.LowPart, create_time.HighPart};
    FILETIME ft_modify_time = { modify_time.LowPart, modify_time.HighPart};
    BOOL isOk = SetFileTime(h, &ft_create_time, NULL, &ft_modify_time);
    if (!isOk) {
        DWORD last_error = GetLastError();
    }

    CloseHandle(h);

    return current;
}

/// \brief Clear a counter, if it exists.
/// \param iCount the counter to clear. Nothing happens if it is zero.
void
CTrialMgr::Clear(const ttstring &sCounterName) {
    ttstring counter_path = GetCounterPath(m_sProgram, sCounterName);

    BOOL isOk = DeleteFile(counter_path.c_str());
    if (!isOk) {
        DWORD last_error = GetLastError();
    }
}
