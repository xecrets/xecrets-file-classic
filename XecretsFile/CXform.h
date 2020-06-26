#ifndef _CXFORM
#define _CXFORM
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
	CXform.h                        File transformation operations such as encrypt/decrypt/compress/decompress/wipe etc

	E-mail                          YYYY-MM-DD              Reason
	software@axantum.com             2001                    Initial
									2002-08-02              Ver 1.2

*/
#include    "CFile.h"
#include    "zlib.h"
#include    "../XecretsFileCommon/CAes.h"
#include    "CSha1.h"
#include    "../XecretsFileCommon/CSubKey.h"
//
//  Basic transformer class - abstract, is instantiated in compress/decompress/encrypt/decrypt/mac/wipe variants.
//
//  As the ZLib guys have done a nice job thinking things out - we steal the z_stream structure with pride!
//
//  This class is mostly an empty wrapper that needs further building to handle buffering etc.
//
class CXform {
public:
	CXform(HWND hProgressWnd);
	~CXform();
	void XformData(CFileIO& utInFile, CFileIO& utOutFile);      // The actual data transformer.
	HWND ProgressWnd() { return m_hProgressWnd; }
private:
	virtual void Xform() = 0;               // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile) = 0; // Empty internal buffers of partially consumed in-data
	virtual void End(CFileIO& utOutFile);   // Close transformation structures if necessary.
protected:
	virtual QWORD Init(CFileIO& utInFile);  // Init transformation structures if necessary.
	void FlushOutStream(CFileIO& utOutFile); // Write all there is in the buffer
//  Update z_stream counters based on consumption
	void ConsumedInOut(DWORD dwIn, DWORD dwOut);
	//
	//  byte-oriented stream-control structure, stolen from ZLib. Nice.
	//
protected:
	z_stream utZstream;
	ulonglong m_cbTotalIn;                  ///< Total bytes read
	ulonglong m_cbTotalOut;                 ///< Total bytes out
	void UpdateZTotalInOut();               ///< Update the long counters with the Zlib short ones
private:
	unsigned long m_cbLastTotal_in;         ///< Used to keep track of how much done since last
	unsigned long m_cbLastTotal_out;        ///< Used to keep track of how much done since last
private:
	HWND m_hProgressWnd;                    // Handle to progress bar control
	BYTE* m_pInBuf;                         // The read buffer to use
	BYTE* m_pOutBuf;                        // The out buffer to use
	void Progress(unsigned int iPercent);   // Update progress indicator.
	void ClearBuffers();
protected:
	virtual void StartProgress();           // Name the operation for the progress window
};
//
//  Compression transformer class
//
//  Throw iErrorCode exception on error
//
class CCompress : public CXform {
public:
	CCompress(HWND hProgressWnd) : CXform(hProgressWnd) {}
	virtual QWORD Init(CFileIO& utInFile);          // Init transformation structures if necessary.
	virtual void Xform();           // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile); // Empty internal buffers of partially consumed in-data
	virtual void End(CFileIO& utOutFile);   // Close transformation structures if necessary.
	virtual void StartProgress();   // Name the operation for the progress window
};
//
//  Compression ratio estimator transformer class.
//  Produces no output - just an estimate of the compression ratio...
//
class CCompressRatio : public CXform {
public:
	CCompressRatio(HWND hProgressWnd) : CXform(NULL) {}
	virtual QWORD Init(CFileIO& utInFile);   // Init transformation structures if necessary.
	virtual void Xform();           // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile); // Empty internal buffers of partially consumed in-data
	virtual void End(CFileIO& utOutFile);   // Close transformation structures if necessary.
	virtual void StartProgress() {} // Name the operation for the progress window
	int GetRatio();                 // return an estimate between 0 and 100. 100 is really good...
private:
	int m_iRatio;
};
//
//  Decompression transformer class
//
//  Throw iErrorCode exception on error
//
class CDecompress : public CXform {
public:
	CDecompress(HWND hProgressWnd) : CXform(hProgressWnd) {}
	virtual QWORD Init(CFileIO& utInFile);          // Init transformation structures if necessary.
	virtual void Xform();           // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile); // Empty internal buffers of partially consumed in-data
	virtual void End(CFileIO& utOutFile);   // Close transformation structures if necessary.
	virtual void StartProgress();   // Name the operation for the progress window
};
//
//  Just copy data from input to output, i.e. the NOP-transform
//
class CNoXform : public CXform {
public:
	CNoXform(HWND hProgressWnd) : CXform(hProgressWnd) {}
	virtual QWORD Init(CFileIO& utInFile);          // Init transformation structures if necessary.
	virtual void Xform();           // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile); // Empty internal buffers of partially consumed in-data
	virtual void End(CFileIO& utOutFile);   // Close transformation structures if necessary.
	virtual void StartProgress() = 0;
};

///< Generic class to handle wiping transformations
class CWipeXform : public CNoXform {
	int m_nWipePasses;
	int m_nPassCurrent;
	DWORD m_dwMsgId;
public:
	CWipeXform(HWND hProgressWnd, DWORD dwMsgId, int nWipePasses = 1) : CNoXform(hProgressWnd) {
		m_nWipePasses = nWipePasses;
		m_dwMsgId = dwMsgId;
		m_nPassCurrent = 1;
	}
	virtual void StartProgress();
};
//
//  File transformer base class for block oriented transformations, i.e.
//  in this context currently encryption and decryption.
//
//  This class is also an abstract class - it cannot be instantiated.
//
//  It adds block buffer functionality to the basic code of the CXform
//  class, which really just wraps the compression/decompression library.
//
class CBlockXform : public CXform {
public:
	CBlockXform(HWND hProgressWnd, DWORD dwBlkSiz = 16);
	~CBlockXform();
	virtual void Xform();           // This is the generic buffer handler shared by derived classes.
	virtual void Xblock(TBlock* putSrc, TBlock* putDst, DWORD dwN = 1) = 0; // Transform blocks.
protected:
	//  For block streams, internal buffer.
	struct {
		BYTE* poIn;                 // Temporary in-buffer to fill up even blocks.
		BYTE* poOut;                // Temp out
		DWORD iIn, iOut;            // # of bytes valid data in respective buffer.
		DWORD dwBlkSiz;             // The size of blocks we are using.
	} m_utBlkBuf;
};
//
//  Encryption transformer class
//
//  Throw iErrorCode exception on error
//
class CEncrypt : public CBlockXform {
public:
	CEncrypt(TKey* putKey, TBlock* putIV, HWND hProgressWnd);
	virtual void Xblock(TBlock* putSrc, TBlock* putDst, DWORD dwN = 1);
	virtual int Finish(CFileIO& utOutFile);
	BYTE GetPadSize(QWORD qwIn);        // With knowledge of the padding algorithm, return pad size
protected:
	BOOL m_bLast;                       // Set when we have padded and encrypted last block.
private:
	CAes m_utAesCryptCBC;               // The encrypt/decrypt context
	virtual void StartProgress();       // Name the operation for the progress window
};
//
//  Decryption transformer class
//
//  Throw iErrorCode exception on error
//
class CDecrypt : public CBlockXform {
public:
	CDecrypt(TKey* putKey, TBlock* putIV, HWND hProgressWnd);
	virtual void Xblock(TBlock* putSrc, TBlock* putDst, DWORD dwN = 1);
	virtual int Finish(CFileIO& utOutFile);
private:
	CAes m_utAesCryptCBC;               // The encrypt/decrypt context
	virtual void StartProgress();       // Name the operation for the progress window
};
//
//  Calculate HMAC according to RFC2104
//
//  The definition of HMAC requires a cryptographic hash function, which
//  we denote by H, and a secret key K. We assume H to be a cryptographic
//  hash function where data is hashed by iterating a basic compression
//  function on blocks of data.   We denote by B the byte-length of such
//  blocks (B=64 for all the above mentioned examples of hash functions),
//  and by L the byte-length of hash outputs (L=16 for MD5, L=20 for
//   SHA-1).  The authentication key K can be of any length up to B, the
//  block length of the hash function.  Applications that use keys longer
//  than B bytes will first hash the key using H and then use the
//  resultant L byte string as the actual key to HMAC. In any case the
//  minimal recommended length for K is L bytes (as the hash output
//  length). See section 3 for more information on keys.
//
//  We define two fixed and different strings ipad and opad as follows
//  (the 'i' and 'o' are mnemonics for inner and outer):
//
//                ipad = the byte 0x36 repeated B times
//                opad = the byte 0x5C repeated B times.
//
//  To compute HMAC over the data `text' we perform
//
//                H(K XOR opad, H(K XOR ipad, text))
//
//   Namely,
//
//    (1) append zeros to the end of K to create a B byte string
//        (e.g., if K is of length 20 bytes and B=64, then K will be
//         appended with 44 zero bytes 0x00)
//    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
//        (1) with ipad
//    (3) append the stream of data 'text' to the B byte string resulting
//        from step (2)
//    (4) apply H to the stream generated in step (3)
//    (5) XOR (bitwise exclusive-OR) the B byte string computed in
//        step (1) with opad
//    (6) append the H result from step (4) to the B byte string
//        resulting from step (5)
//    (7) apply H to the stream generated in step (6) and output
//        the result
//
//  As the key, we generate a key from the DataEncryptingKey by encrypting One.
//
class CHmac : public CXform {
public:
	CHmac(TKey* pDataEncKey, HWND hProgressWnd);
	~CHmac();

	virtual QWORD Init(CFileIO& utInFile);          // Init transformation structures if necessary.
	virtual void Xform();           // Regular transformation of data until end of in-data
	virtual int Finish(CFileIO& utOutFile); // Empty internal buffers of partially consumed in-data
	THmac* GetHMAC();               // Return pointer to the generated HMAC.
private:
	void XorPad(BYTE oPad);         // Helper for inner and outer Xor and padding.
	SHA1_CTX* m_putContext;         // Context used by the SHA-1 library code
	CSubKey m_utHMACKey;            // The generated subkey used to calculate the HMAC
	THash* m_putHMAC;               // The calculated HMAC.
	virtual void StartProgress();       // Name the operation for the progress window
};
#endif  _CXFORM