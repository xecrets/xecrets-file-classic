/*
    @(#) $Id$

	AxCrypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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

	The author may be reached at mailto:axcrypt@axondata.se and http://axcrypt.sourceforge.net
----
	CXform.cpp						File transformation operations such as encrypt/decrypt/compress/decompress/wipe etc
	
	E-mail							YYYY-MM-DD				Reason
	axcrypt@axondata.se 			2001					Initial
									2001-11-27				Fixed loop in CWipe with partial wipe > 1K
                                    2002-08-02              Rev 1.2

*/
#include	"StdAfx.h"
#include	"CXform.h"
#include    "../AxCryptCommon/CVersion.h"
#include    "../AxCryptCommon/CRegistry.h"
#include    "commctrl.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CXform.cpp"
//
//	Initialize the stream structure. Mostly for ZLib purposes, but we use the data counters
//	for the other derived classes as well.
//
CXform::CXform(HWND hProgressWnd) {
    m_hProgressWnd = hProgressWnd;

	utZstream.zalloc = (alloc_func)0;
	utZstream.zfree = (free_func)0;
	utZstream.opaque = (voidpf)0;

    // Allocate these, potentially large, buffers directly from the OS. There is a slight risk
    // that clear-text data will through these migrate to the swapfile, but we run that risk
    // anyway if we're editing or whatever. The important thing is to keep key-material off the
    // disk and the swap file, and for that we have the "secure" heap.
    m_pInBuf = (BYTE *)VirtualAlloc(NULL, MAX_VIEW_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSAPI(m_pInBuf != NULL);

    m_pOutBuf = (BYTE *)VirtualAlloc(NULL, MAX_VIEW_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSAPI(m_pOutBuf != NULL);

    ClearBuffers();
}
/// \brief Clean up buffer
CXform::~CXform() {
    // Clearing the memory immediately before a release may well be a no-op, but it's fairly quick
    // and will do no harm, hopefully.
    ZeroMemory(m_pInBuf, MAX_VIEW_SIZE);
    ASSAPI(VirtualFree(m_pInBuf, 0, MEM_RELEASE));

    ZeroMemory(m_pOutBuf, MAX_VIEW_SIZE);
    ASSAPI(VirtualFree(m_pOutBuf, 0, MEM_RELEASE));
}

void
CXform::ClearBuffers() {
	// Initialize the stream
	utZstream.avail_in = 0;
	utZstream.total_in = 0;
	utZstream.total_out = 0;

    m_cbTotalIn = m_cbTotalOut = 0;
    m_cbLastTotal_in = m_cbLastTotal_out = 0;

    // Initialize the output buffer so that it's ready for use. The FlushOutStream() code gets confused
    // otherwise and thinks it has something to write, which it doesn't.
    utZstream.avail_out = MAX_VIEW_SIZE;
    utZstream.next_out = m_pOutBuf;
}

//
//  Default init
//
/*virtual*/ QWORD
CXform::Init(CFileIO& utInFile) {
    return utInFile.m_qwFileSize - utInFile.GetFilePointer();
}
//
//	Generic data transformation using a stream to control in and out. It will
//	read and write to the stream, which ensure that all blocking and buffering
//	requirements are met.
//
//	This class job is to get and provide streams of bytes to the underlying
//	algorithms which include compression/decompress/encryption/decryption/hashing/wiping etc.
//
void
CXform::XformData(CFileIO& utInFile, CFileIO& utOutFile) {
	HEAP_CHECK_BEGIN(_T("CXform::XformData()"), 0);

	QWORD qwTotalInputSize = Init(utInFile);
	CAssert(qwTotalInputSize >= 0).File(MSG_FILE_LENGTH, utInFile.FileName()).Throw();
    
    // Set the name of the operation in the progress window, if any
    StartProgress();

    // Do the transformation, in multiple segments if necessary.
    QWORD cbRemaining;
	while (cbRemaining = qwTotalInputSize - m_cbTotalIn) {
        // Don't try to read more than we're supposed to.
        size_t avail_in = cbRemaining > MAX_VIEW_SIZE ? MAX_VIEW_SIZE : (unsigned int)cbRemaining;
        utInFile.ReadData(utZstream.next_in = m_pInBuf, &avail_in);
		utZstream.avail_in = (uInt)avail_in;

        // Now consume all input to be compressed in this segment.
		while (utZstream.avail_in > 0) {
            // Update progress bar, use different strategies for cases where
            // times 100 risks an overflow, and when it does not.
            if (qwTotalInputSize < 0x80000000) {
                QWORD qwConsumedTimes100 = m_cbTotalIn * 100;
                Progress((unsigned int)(qwConsumedTimes100 / qwTotalInputSize));
            } else {
                QWORD qwSizeDiv100 = qwTotalInputSize / 100;
                Progress((unsigned int)(m_cbTotalIn / qwSizeDiv100));
            }
            FlushOutStream(utOutFile);
			Xform();
		}
	}
	// Flush the final stuff. If necessary, make room for possible last squirt.
	do {
        FlushOutStream(utOutFile);
	} while (Finish(utOutFile));
    FlushOutStream(utOutFile);
	End(utOutFile);
	utOutFile.SetEndOfFile();
	utOutFile.FlushBuffers();
    utOutFile.m_qwFileSize = utOutFile.GetFileSize();

    // If we re-use the transform, re-initalize it so we can use it without constructing it again.
    ClearBuffers();

    HEAP_CHECK_END
	return;
}

void
CXform::FlushOutStream(CFileIO& utOutFile) {
    // Actually write the buffer
    size_t cb = MAX_VIEW_SIZE - utZstream.avail_out;
    if (cb) {
        utOutFile.WriteData(utZstream.next_out = m_pOutBuf, &cb);
        utZstream.avail_out = MAX_VIEW_SIZE;
    }
}

void
CXform::End(CFileIO& utOutFile) {
}

//
//	Helper for my stream handlers that use the z_stream structure from ZLib.
//
void
CXform::ConsumedInOut(DWORD dwIn, DWORD dwOut) {
	utZstream.avail_in -= dwIn;
	m_cbTotalIn += dwIn;
	utZstream.next_in += dwIn;

	utZstream.avail_out -= dwOut;
	m_cbTotalOut += dwOut;
	utZstream.next_out += dwOut;
}

/// \brief Update our long total-counters with the short zlib ones
void
CXform::UpdateZTotalInOut() {
    // We need to keep our own large counters of processed bytes as zlib does not,
    // apparently will not - I did submit diffs and all... But it appears that they
    // want it done this way, so we'll do it that way to avoid the need to keep
    // patching each new version.

    // It appears we're not allowed to modify the total_in, total_out counters...
    m_cbTotalIn += utZstream.total_in - m_cbLastTotal_in;
    m_cbTotalOut += utZstream.total_out - m_cbLastTotal_out;

    m_cbLastTotal_in = utZstream.total_in;
    m_cbLastTotal_out = utZstream.total_out;
}

//
// Update progress indicator.
//
void
CXform::Progress(unsigned int iPercent) {
    if (m_hProgressWnd != NULL) {
        if (!GetWindowLongPtr(GetParent(m_hProgressWnd), GWLP_USERDATA)) {
            CAssert(GetLastError() == ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CXform::Progress() [GetWindowLong()]")).Throw();
            // Stop and hide the window, restoring to normal, since we've detected one cancel. If the caller doesn't re-initialize
            // properly, we may get into an infinite cancel-loop otherwise, since we'll think it's always cancelled, even if the
            // user gets to retry after cancel.
            SendMessage(GetParent(m_hProgressWnd), WM_APP, 0, 0);
            CAssert(FALSE).App(WRN_CANCEL).Throw();
        }
        PostMessage(m_hProgressWnd, PBM_SETPOS, (WPARAM)(iPercent > 100 ? 100 : iPercent), 0);
    }
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CXform::StartProgress() {
    if (m_hProgressWnd != NULL) {
        // Clear the operation text. Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)_T(""));

        // Start the visual wait timer, use send message to ensure sequence.
        SendMessage(GetParent(m_hProgressWnd), WM_APP + 2, 0, 0);
    }
}

//
//	Wrap ZLib Init()
//
/*virtual*/ QWORD
CCompress::Init(CFileIO& utInFile) {
	CAssert(deflateInit(&utZstream, Z_DEFAULT_COMPRESSION) == Z_OK).App(MSG_DEFLATE_INIT).Throw();
    return utInFile.m_qwFileSize - utInFile.GetFilePointer();
}
//
//	Call deflate for each section of data from the input file as it appears.
//
/*virtual*/ void CCompress::Xform() {
    do {
        unsigned long cb = 0;
        
        if (utZstream.avail_in > ZLIB_FULL_FLUSH_SIZE) {
            cb = utZstream.avail_in - ZLIB_FULL_FLUSH_SIZE;
            utZstream.avail_in = ZLIB_FULL_FLUSH_SIZE;
        }

        int iRet = deflate(&utZstream, Z_FULL_FLUSH);
        utZstream.avail_in += cb;

        UpdateZTotalInOut();
	    CAssert(iRet == Z_OK).App(MSG_DEFLATE_SYNC).Throw();
    } while (utZstream.avail_in && utZstream.avail_out);
}
//
//	Flush all buffers and write the last output to the output buffer
//
/*virtual*/ int
CCompress::Finish(CFileIO& utOutFile) {
    int iReturn = deflate(&utZstream, Z_FINISH);
    UpdateZTotalInOut();

    if (iReturn == Z_OK) return TRUE;

	CAssert(iReturn == Z_STREAM_END).App(MSG_COMPRESS_FINISH).Throw();
	return FALSE;
}
//
//	Free datastructures etc.
//
/*virtual*/ void
CCompress::End(CFileIO& utOutFile) {
	CAssert(deflateEnd(&utZstream) == Z_OK).App(MSG_COMPRESS_FINISH).Throw();
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CCompress::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)(LPTSTR)CMessage().AppMsg(INF_OPNAME_COMPRESS).GetMsg());
    }
}
//
//	Wrap ZLib Init(), and limit reading of the file to the start for this purpose.
//
/*virtual*/ QWORD
CCompressRatio::Init(CFileIO& utInFile) {
	CAssert(deflateInit(&utZstream, Z_DEFAULT_COMPRESSION) == Z_OK).App(MSG_DEFLATE_INIT).Throw();
    if (CXform::Init(utInFile) < COMPRESS_TEST_SIZE) {
        return CXform::Init(utInFile);
    } else {
        return COMPRESS_TEST_SIZE;
    }
}
//
//	Call deflate for each section of data from the input file as it appears.
//
/*virtual*/ void
CCompressRatio::Xform() {
    int iRet = deflate(&utZstream, Z_SYNC_FLUSH);
    UpdateZTotalInOut();
	CAssert(iRet == Z_OK).App(MSG_DEFLATE_SYNC).Throw();
}

//
//	Flush all buffers and write the last output to the output buffer
//
/*virtual*/ int
CCompressRatio::Finish(CFileIO& utOutFile) {
	int iReturn = deflate(&utZstream, Z_FINISH);
    UpdateZTotalInOut();
	if (iReturn == Z_OK) return TRUE;

	CAssert(iReturn == Z_STREAM_END).App(MSG_COMPRESS_FINISH).Throw();
	return FALSE;
}
//
//	Free datastructures etc.
//
/*virtual*/ void
CCompressRatio::End(CFileIO& utOutFile) {
	CAssert(deflateEnd(&utZstream) == Z_OK).App(MSG_COMPRESS_FINISH).Throw();
    //
    // Some tricks to keep to integer arithmetic without risk of overflow etc,
    // calculate the ratio between the diference of out and in.
    // 100 is perfect compress, 0 is no compression.
    //
    QWORD qwTemp = m_cbTotalIn / 100;
    if (qwTemp > 0) {
        m_iRatio =  (int)(100 - m_cbTotalOut / qwTemp);
    } else if (m_cbTotalIn > 0) {
        m_iRatio =  (int)(100 - m_cbTotalOut * 100 / m_cbTotalIn);
    } else {
        m_iRatio = 0;
    }

    if (m_iRatio < 0) {
        m_iRatio = 0;
    }

    if (m_iRatio > 100) {
        m_iRatio = 100;
    }
}
//
//  Return the calculated compression ratio.
//
int
CCompressRatio::GetRatio() {
    return m_iRatio;
}
//
//	Decompress transformer class begins here
//
//	Wrap ZLib inflateInit()
//	
/*virtual*/ QWORD
CDecompress::Init(CFileIO& utInFile) {
	utZstream.next_in = Z_NULL;	// Defer check to first call to inflate
	CAssert(inflateInit(&utZstream) == Z_OK).App(MSG_INFLATE_INIT).Throw();
    return utInFile.m_qwFileSize - utInFile.GetFilePointer();
}
//
//	Wrap ZLib call to inflate() for each segment as it arrives from the input
//
/*virtual*/ void
CDecompress::Xform() {
    int iReturn = inflate(&utZstream, 0);
    UpdateZTotalInOut();
	CAssert((iReturn == Z_OK) || (iReturn == Z_STREAM_END)).App(MSG_INFLATE_ERROR).Throw();
}
//
//	Wrap ZLib call to flush its buffers to the output file
//
/*virtual*/ int
CDecompress::Finish(CFileIO& utOutFile) {
	int iReturn = inflate(&utZstream, 0);
    UpdateZTotalInOut();
	if (iReturn == Z_OK) return TRUE;

    CAssert(iReturn == Z_STREAM_END).App(MSG_INFLATE_FINISH).Throw();
	return FALSE;
}
//
//	Wrap ZLib call to End() to clear it's data structures.
//
/*virtual*/ void
CDecompress::End(CFileIO& utOutFile) {
	CAssert(inflateEnd(&utZstream) == Z_OK).App(MSG_INFLATE_END).Throw();
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CDecompress::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)(LPTSTR)CMessage().AppMsg(INF_OPNAME_DECOMPRESS).GetMsg());
    }
}

/*virtual*/ QWORD
CNoXform::Init(CFileIO& utInFile) {
    return utInFile.m_qwFileSize - utInFile.GetFilePointer();
}
//
//	Fill all available out-space with pseudo-random data.
//
/*virtual*/ void
CNoXform::Xform() {
	// it is the in-file which determines how much to copy, as we are doing a pseudo-transformation.
	DWORD dwLen = Min(utZstream.avail_in, utZstream.avail_out);
    CopyMemory(utZstream.next_out, utZstream.next_in, dwLen);
	ConsumedInOut(dwLen, dwLen);
}
//
//	As we do not internally buffer anything - nothing need be done here.
//	FALSE return means "Don't call me again, I'm done."
//
/*virtual*/ int
CNoXform::Finish(CFileIO& utOutFile) {
	return FALSE;
}
//
//	No cleaning up is necessary either.
//
/*virtual*/ void
CNoXform::End(CFileIO& utOutFile) {
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CWipeXform::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        TCHAR szMsg[200];
        if (m_nWipePasses == 0 || m_nWipePasses == 1) {
            _sntprintf_s(szMsg, sizeof szMsg / sizeof szMsg[0], sizeof szMsg / sizeof szMsg[0], _T("%s"), (LPTSTR)CMessage().AppMsg(m_dwMsgId).GetMsg());
        } else {
            _sntprintf_s(szMsg, sizeof szMsg / sizeof szMsg[0], sizeof szMsg / sizeof szMsg[0], _T("%s (%d/%d)"), (LPTSTR)CMessage().AppMsg(m_dwMsgId).GetMsg(), m_nPassCurrent, m_nWipePasses);
            m_nPassCurrent++;
        }
        szMsg[sizeof szMsg / sizeof szMsg[0] - 1] = _T('\0');
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)szMsg);
    }
}
//
//	CBlockXform
//
//	Abstract base class for block-oriented transformer classes
//	begins here.
//	It helps implement transformations that needs input in fixed
//	block sizes, and buffers data appropriately regardless of how
//	the byte stream arrives.
//	Specifically encryption/decryption, but it may be used for other
//	cases as well.
//
CBlockXform::CBlockXform(HWND hProgressWnd, DWORD dwBlkSiz) : CXform(hProgressWnd) {
	// Initialize the stream temp block
	m_utBlkBuf.dwBlkSiz = dwBlkSiz;				// Set-up block size
	m_utBlkBuf.poIn = new BYTE[m_utBlkBuf.dwBlkSiz];	// need to be secure, as they may contain cleartext.
    ASSPTR(m_utBlkBuf.poIn);

    m_utBlkBuf.poOut = new BYTE[m_utBlkBuf.dwBlkSiz];
    ASSPTR(m_utBlkBuf.poOut);

	m_utBlkBuf.iIn = m_utBlkBuf.iOut = 0;
}

CBlockXform::~CBlockXform() {
	delete m_utBlkBuf.poIn;
	delete m_utBlkBuf.poOut;
}
//
//	Generic encrypt/decrypt block-buffering, ensuring that the stream is treated block-wise, regardless
//	of how the data is fed in, and how space is made available out.
//
//	If any motion of data is possible, it will be done. Not necessarily *all* though, several calls
//	may be needed given any specific "starting" point.
//
void
CBlockXform::Xform() {
	DWORD i, j;
	// If we can/need to write anything from the block buffer...
	if (i = Min(m_utBlkBuf.iOut, utZstream.avail_out)) {
		CopyMemory(utZstream.next_out, &m_utBlkBuf.poOut[m_utBlkBuf.dwBlkSiz - m_utBlkBuf.iOut], i);
		m_utBlkBuf.iOut -= i;
		ConsumedInOut(0, i);
	}
	if (m_utBlkBuf.iOut) return;			// Partial output block left. Need more avail_out to continue.
	if (utZstream.avail_in == 0) return;	// Nothing more to do.

	// Check if we need to buffer a partial input block.
	// Mininum of avail_in and available space in block buffer (if dwBlkSiz it is empty),
	// thus the maximum value of this is dwBlkSiz, indicating that at least one complete
	// block is available for input.
	i = Min(utZstream.avail_in, (DWORD)(m_utBlkBuf.dwBlkSiz - m_utBlkBuf.iIn));
	// Calculate how many complete blocks can be processed from in to out, which
	// is the minimum of # of blocks in in-stream and # of blocks in out-stream.
	j = Min(utZstream.avail_in, utZstream.avail_out) / m_utBlkBuf.dwBlkSiz;	// # of blocks.

	// if less than a block is avail_in or there is data in in the block input buffer
	// OR
	// if there is at least a full block avail_in but there is not a full block avail_out.
	if (i < m_utBlkBuf.dwBlkSiz || // If this is FALSE, at least 1 block is availble from in-stream...
		j == 0) { // ... thus if this is TRUE, the problem is that wee need more out-stream space,
				  // but we can consume from in-stream to block buffer, which we do.
		// Copy data from instream to the buffer.
		CopyMemory(m_utBlkBuf.poIn + m_utBlkBuf.iIn, utZstream.next_in, i);
		m_utBlkBuf.iIn += i;
		ConsumedInOut(i, 0);
		// Check to see if we have a full block ready for encryption/decryption
		if (m_utBlkBuf.iIn == m_utBlkBuf.dwBlkSiz) {
			Xblock((TBlock *)m_utBlkBuf.poIn, (TBlock *)m_utBlkBuf.poOut);
			m_utBlkBuf.iOut = m_utBlkBuf.dwBlkSiz;
			m_utBlkBuf.iIn = 0;
		}
		return;								// Enough so far, we'll be back shortly at the top...
	} else {
		// This is a slight optimization - if one relaxes the first constraint above, all data
		// will go through that part of the code, one block at a time. But most data will be
		// in large chunks, so we do it in one call here, and have the loop deeper down instead
		// saving some overhead/block as well as bypassing the block-buffer.
		// No partial blocks remain, and we have at least one full block in the instream.
		Xblock((TBlock *)utZstream.next_in, (TBlock *)utZstream.next_out, j);
		ConsumedInOut(j * m_utBlkBuf.dwBlkSiz, j * m_utBlkBuf.dwBlkSiz);
	}
	// Happy so far. If there is a partial in-block left, next round will handle it.
}
// Constructor
CEncrypt::CEncrypt(TKey *putKey, TBlock *putIV, HWND hProgressWnd) : CBlockXform(hProgressWnd) {
	m_utAesCryptCBC.Init(putKey, CAes::eCBC, CAes::eEncrypt);
	m_utAesCryptCBC.SetIV(putIV);
	m_bLast = FALSE;
}

/*virtual*/ void
CEncrypt::Xblock(TBlock *putSrc, TBlock *putDst, DWORD dwN) {
	m_utAesCryptCBC.Xblock(putSrc, putDst, dwN);
}
//
//	When we get here avail_in is zero, so all in-stream data is consumed.
//	If the last block was filled, we known that "Xform" will always move
//	that to the out-buffer in the same call as it is consumed.
//
//	Thus, after emptying the out-buffer, we either have data to be padded
//	in in-buffer or an empty in-buffer that needs to be filled with all
//	padding.
//
//	This function may be called multiple times. Return TRUE if there
//	is more to do, and you would like to be called again...
//
int
CEncrypt::Finish(CFileIO& utOutFile) {
	Xform();							// Flush possibly full outbuffer block.
	if (m_utBlkBuf.iOut) return TRUE;	// Need more outbuffer before proceeding

	if (!m_bLast) {
		// Fill the in-buffer with padding according to RFC 1423 adapted to 16-byte blocks
		for (DWORD i = m_utBlkBuf.iIn; i < m_utBlkBuf.dwBlkSiz; i++) {
			m_utBlkBuf.poIn[i] = (BYTE)(m_utBlkBuf.dwBlkSiz - m_utBlkBuf.iIn);
		}
		// Encrypt the block, and make it ready for output.
		Xblock((TBlock *)m_utBlkBuf.poIn, (TBlock *)m_utBlkBuf.poOut);
		m_utBlkBuf.iIn = 0;
		m_utBlkBuf.iOut = m_utBlkBuf.dwBlkSiz;
		m_bLast = TRUE;
		return TRUE;					// Come back for more!
	}
	// No data in out-block-buf, Have made the padding block -> done!
	return FALSE;
}
//
//	Knowing the padding algorithm, we calculate what the total size of the data produced will be.
//	Standard padding will pad up to even m_utBlkBuf.dwBlkSiz-byte boundary, when data is even m_utBlkBuf.dwBlkSiz-byte, an extra
//	block of only padding will be produced.
//
//	The padding scheme is from RFC 1423 adapted to 16-byte blocks
//
BYTE
CEncrypt::GetPadSize(QWORD qwIn) {
	return (BYTE)(m_utBlkBuf.dwBlkSiz - qwIn % m_utBlkBuf.dwBlkSiz);
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CEncrypt::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)(LPTSTR)CMessage().AppMsg(INF_OPNAME_ENCRYPT).GetMsg());
    }
}
// Constructor
CDecrypt::CDecrypt(TKey *putKey, TBlock *putIV, HWND hProgressWnd) : CBlockXform(hProgressWnd) {
	m_utAesCryptCBC.Init(putKey, CAes::eCBC, CAes::eDecrypt);
	m_utAesCryptCBC.SetIV(putIV);
}

/*virtual*/ void
CDecrypt::Xblock(TBlock *putSrc, TBlock *putDst, DWORD dwN) {
	m_utAesCryptCBC.Xblock(putSrc, putDst, dwN);
}
//
//	Return TRUE while more data to flush! We know here there is no more data to read.
//
//  At this point, we may in fact have decrypted the whole thing - in fact we most likely have,
//  as it's unlikely the encrypted data is fed to the decryption in anything but even blocks, and
//  the output buffer is likely a multiple of the block size.
//
//	The data about the padding length is in the last block.
//	The padding scheme is from RFC 1423 adapted to 16-byte blocks
//
//	Two general cases exist: A full block of padding, or a mixed block with both padding
//	and data. Regardless, we know that the last block will have padding.
//
int
CDecrypt::Finish(CFileIO& utOutFile) {
    // Since we know at the start that avail_in is zero when we're called, we can at most
    // have one block we need to flush out - which will always be the padding block. It may
    // also already be written.
	Xform();							// Flush (possibly full) outbuffer block.
	if (m_utBlkBuf.iOut) return TRUE;	// Need more outbuffer before proceeding

    // Ensure that we've actually written all to the file
    FlushOutStream(utOutFile);

    // At this point we know that we've written one block with padding - but we don't really
    // know what it is...
    utOutFile.SetFilePointer(utOutFile.GetFilePointer() - m_utBlkBuf.dwBlkSiz);
    size_t cb = m_utBlkBuf.dwBlkSiz;
    utOutFile.ReadData(m_utBlkBuf.poOut, &cb);
    CAssert(cb == m_utBlkBuf.dwBlkSiz).App(MSG_PAD_ERROR).Throw();

    // At this point, we should only have padding left as output data, assuming
	// there was enough space in the output buffer to contain it.
	unsigned int iPad = m_utBlkBuf.poOut[m_utBlkBuf.dwBlkSiz - 1];

    // Before finally ending - check that the padding is correct.
	for (unsigned int i = m_utBlkBuf.dwBlkSiz - iPad; i < m_utBlkBuf.dwBlkSiz; i++) {
		CAssert(m_utBlkBuf.poOut[i] == iPad).App(MSG_PAD_ERROR).Throw();
	}

    // Rewind to not persist the padding
    utOutFile.SetFilePointer(utOutFile.GetFilePointer() - iPad);
	return FALSE;
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CDecrypt::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)(LPTSTR)CMessage().AppMsg(INF_OPNAME_DECRYPT).GetMsg());
    }
}
//
//	Calculate the RFC2104 HMAC
//
CHmac::CHmac(TKey *pDataEncKey, HWND hProgressWnd) : CXform(hProgressWnd) {
	m_putContext = new SHA1_CTX;
    ASSPTR(m_putContext);

	m_putHMAC = new THash;
    ASSPTR(m_putHMAC);

	// Generate the sub key
	m_utHMACKey.Set(pDataEncKey, CSubKey::eHMAC);
}
//
//	Destroy the temporary values. Important that they are on the heap.
//
CHmac::~CHmac() {
	if (m_putContext != NULL) delete m_putContext;
	if (m_putHMAC != NULL) delete m_putHMAC;
}
//
//	Do the initial inner padding, xor and hashing of that.
//
/*virtual*/ QWORD
CHmac::Init(CFileIO& utInFile) {
	SHA1Init(m_putContext);

	// K xor ipad
	XorPad(0x36);
	SHA1Update(m_putContext, (BYTE *)m_putHMAC, sizeof *m_putHMAC);
    return utInFile.m_qwFileSize - utInFile.GetFilePointer();
}
//
//	Hash all data in the inner 'loop'.
//
/*virtual*/ void
CHmac::Xform() {
	SHA1Update(m_putContext, utZstream.next_in, utZstream.avail_in);
	ConsumedInOut(utZstream.avail_in, 0);
}
//
//	Take the MAC key, xor with the outer value and pad,
//	append the previous hash, and produce the final
//	HMAC-SHA1 result.
//
/*virtual*/ int
CHmac::Finish(CFileIO& utOutFile) {
	THash *putHash = new THash;
    ASSPTR(putHash);

	SHA1Final((BYTE *)putHash, m_putContext);

	// K xor opad
	XorPad(0x5c);
	// Now do the outer hash.
	SHA1Init(m_putContext);
	SHA1Update(m_putContext, (BYTE *)m_putHMAC, sizeof *m_putHMAC);
	SHA1Update(m_putContext, (BYTE *)putHash, sizeof *putHash);
	SHA1Final((BYTE *)m_putHMAC, m_putContext);
	delete putHash;
	return FALSE;
}
//
//	Return the result. The Hmac() call may truncate.
//
THmac *
CHmac::GetHMAC() {
	return m_putHMAC->Hmac();
}
//
//	Helper for the inner and outer padding and Xor
//
void CHmac::XorPad(BYTE oPad) {
	for  (int i=0; i < sizeof *m_putHMAC; i++) {
		((BYTE *)m_putHMAC)[i] = oPad;
		if (i < sizeof *m_utHMACKey.Get()) {
			((BYTE *)m_putHMAC)[i] ^= ((BYTE *)m_utHMACKey.Get())[i];
		}
	}
}
//
// Name the operation for the progress window
//
/*virtual*/ void
CHmac::StartProgress() {
    CXform::StartProgress();
    if (ProgressWnd() != NULL) {
        // Need to use SendMessage to cross process boundary
        SendMessage(GetDlgItem(GetParent(ProgressWnd()), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)(LPTSTR)CMessage().AppMsg(INF_OPNAME_HMAC).GetMsg());
    }
}
