#ifndef XECRETSFILELIB_H
#define XECRETSFILELIB_H
/*! \file
	\brief XecretsFileLib.h - An Xecrets File Classic support library

	@(#) $Id$

	XecretsFileLib - An Xecrets File Classic support library

	This interface may be used directly by code implementing Xecrets File Classic-functions.

	The library is built around a single parameter buffer, which is a struct AXCL_PARAM
	and various function calls, passing this parameter buffer and other things as parameters.

	There are operations to encrypt, decrypt, reencrypt and get encrypted meta data.
	There is also an independent set of operations to manage a cache of keys.

	The operations and their parameters are defined as C-style functions, structures, pre-processor defines
	and enums to make the library maximally useful by callers. Internally it's still C++.
	The operations are defined as separate functions to enable minimal builds by excluding unused code in
	the linker.

	The library is OS and environment independent, and uses callbacks as it's mechanism to implement
	specifics and dependencies of such nature. The user of the library must specify the address of
	a callback function, with the signature typedef void *XecretsFileLibCallbackT(AXCL_PARAM *, int iCallbackAction) .

	Typical actions are AXCL_A_PROGRESS to report progress and check for cancel, AXCL_A_GET_CIPHER_PATH to get
	the full path to encipher to, possibly via a user dialog, AXCL_A_GET_PLAIN_PATH to get the full path
	to decrypto to, possilby via a user dialog and AXCL_A_TCHAR2ANSI and AXCL_A_ANSI2TCHAR to convert to and
	from Ansi respectively.

	The library uses it's own pretty-much-compatible version of the Windows API concept of a _TCHAR for
	a mutable character type that may be wide or not depending on compilation options, and it defines
	the necessary types and macros for this. Windows programmers should be aware that _TT is used instead
	of _T to avoid collissions with the Windows definition. You control if _TCHAR is wide by defining the
	preprocessor constant _UNICODE. If _TCHAR is not wide, i.e. _UNICODE is not defined, conversion to and
	from Ansi is a null operation. There is no support for UTF-8 encoding of Unicode in a 'char'.

	All memory allocation/deallocation is handled internally by the library by new/delete. Do not copy pointers, only
	data from the library, do not attempt to free/delete any data from the library. If the application
	requires secure memory handling, this must be achieved by overriding the global new and delete operators. The library
	does not use malloc/free explicitly.

	All paths and strings are communicated as TCHAR's, i.e. potentially Unicode, but not necessarily.

	The following basic operations are supported by the library:

	- Encrypt a file
	- Decrypt a file
	- Re-encrypt a file under a different passphrase - this does not actually change the master-key, only the key-encrypting-key
	- Determine meta information from the headers, such as file-times, and plain-file name. Possibly size etc too.

	The typical encryption process is:

		- The caller determines the full path of the plain-text input
		- The caller determines the file name of the plain-text to store in the encrypted result
		- The caller determines the file times of the input file
		- The caller gets a parameter structure, providing it's own context info etc.
		- The caller optionally determines the passphrase and key-file, and calls the library to hash this to a key encrypting key OR ...
		- ... determines the key encrypting key by some other means, such as retrieving it from a store or cache using a fingerprint
		- The caller requests encryption with the parameters (parameter structure (with kek and file times), full path, plain file name)
		- The library opens the plain-text, starts the encryption process AND ...
		- ... calls back to convert the plain-text file name to Ansi AND ...
		- ... calls back to determine the output path, providing the parameter block as a help. The result is a full path to the output, which is copied.
		- The library then creates the output file, starts the encryption AND ...
		- ... periodically calls back to report progress and check for cancellation in the same call.
		- When the encryption is finished, or cancel is requested, all resources are freed and the original call to Encrypt returns with appropriate status
		- The caller does any further processing of file attributes such as file times, read-only etc etc

	For encryption we need:

		- A callback to get a full encryption result path AXCL_PATHOUT, given a default result path AXCL_PATHOUT
		- A callback to explicitly (possibly null) convert from TCHAR's iBuf to char's 'charString', with the option to ask for buffer size

	The decryption process is:

		- The caller determines the full path of the cipher-text input file
		- The caller optionally determines the passphrase and key-file, and calls the library to hash this to a key encrypting key OR ...
		- ... determines the key encrypting key by some other means, such as retrieving it from a store or cache
		- The caller requests decryption with the pair (full path, key encrypting key) plus suggested output path
		- The library opens the cipher-text, and attempts to decrypt the headers with the provided key encrypting key and EITHER ...
		- ... returns with an error code stating that the provided key was wrong OR ...
		- ... starts the decryption process, AND ...
		- ... calls back to convert the file name from the headers to TCHAR AND...
		- ... calls back to determine the output path, providing the suggested output path plus the file name found in the headers. The callback MAY ...
		- ... call the library to reallocate the output path buffer, and update it. The result is a full path to the output.
		- The library then creates the output file, continues the decryption, stores the original file times from the headers AND ...
		- ... periodically calls back to report progress and check for cancellation in the same call.
		- When the decryption is finished, or cancel is requested, all resources are freed and the original call to Decrypt returns with appropriate status
		- The caller does any further processing of file attributes such as file times, read-only etc
		- The caller provides logic for launching if required

	For decryption we need:
		- A callback to get a full decryption result path AXCL_PATHOUT, given a default result path AXCL_PATHOUT
		- A callback to explicitly (possilby null) convert from char's 'charString' to TCHAR's iBuf, with the option to ask for buffer size

	Re-encrypt process is:

		- The caller determins the full path of the cipher-text input file
		- The caller optionally determines the old passphrase and key-file, and calls the library to hash this to a key encrypting key OR ...
		- ... determines the key encrypting key by some other means, such as retrieving it from a store or cache
		- The caller optionally determines the new passphrase and key-file, and calls the library to hash this to a key encrypting key OR ...
		- ... determines the key encrypting key by some other means, such as retrieving it from a store or cache
		- The caller requests re-encryption with the parameters (full input path, old key-enc-key, new key-enc-key)
		- The caller opens the input file, verifies and recalculates the HMAC at the same time AND ...
		- ... periodically calls back to report progress and check for cancellation in the same call.
		- When the operation is finished, or cancel is requested, all resources are freed and the original library call returns with appropriate status
		- The caller does any further processing of file attributes such as file times, read-only etc

	Get meta info process is:
		- The caller determins the full path of the cipher-text input file
		- The caller optionally determines the decryption passphrase and key-file, and calls the library to hash this to a key encrypting key OR ...
		- ... determines the key encrypting key by some other means, such as retrieving it from a store or cache
		- The caller requetss meta data with the parameters (full input path, dec key-enc-key)
		- The caller opens the input file, decrypts the headers and optionally verifies the HMAC AND ...
		- ... periodically calls back to report progress and check for cancellation in the same call.
		- When the operation is finished, or cancel is requested, all resources are freed and the original library call returns with appropriate status

	Common stuff:
		- AXCL_PATHIN The full path name used to open the input file. We assume that AxPipe is capable of portably opening it.
		- A callable function to (re-)allocate memory for AXCL_PATHOUT, AXCL_PATHIN, AXCL_PATHKEY, AXCL_FILENAME
		- A callable function to hash a passphrase 'pPassphrase/cbPassphrase' and possibly a key-file AXCL_PATHKEY to a key encrypting key pKEK/cbKEK.
		- A callback to report progress in the scale of 0-10000, and check for cancellation

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
*/

#include "AxAssert.h"
#define AXLIB_ASSERT_FILE "XecretsFileLib.h"

// A few Windows syntax-compatible definitions for Unicode/Non-Unicode builds
// Because it's not possible to be compatible with tchar.h for the definition of _T
// this code uses _TT instead.
#ifndef _TT
#ifdef _T
#define _TT _T
#else
#ifdef _UNICODE
#define _TT(x) L ## x
#else
#define _TT
#endif // _UNICODE
#endif // _T
#endif // _TT

#ifdef _UNICODE

#ifndef _WCTYPE_T_DEFINED
typedef unsigned short wint_t;
typedef unsigned short wctype_t;
#define _WCTYPE_T_DEFINED
#endif // _WCTYPE_T_DEFINED

#ifndef __TCHAR_DEFINED
typedef wchar_t _TCHAR;
typedef wchar_t _TSCHAR;
typedef wchar_t _TUCHAR;
typedef wchar_t _TXCHAR;
typedef wint_t _TINT;
#define __TCHAR_DEFINED
#endif // __TCHAR_DEFINED

#else // !_UNICODE

#ifndef __TCHAR_DEFINED
typedef char _TCHAR;
typedef signed char _TSCHAR;
typedef unsigned char _TUCHAR;

#ifdef _MBCS
typedef unsigned char _TXCHAR;
typedef unsigned int _TINT;
#else
typedef char _TXCHAR;
typedef int _TINT;
#endif // _MBCS

#define __TCHAR_DEFINED
#endif // __TCHAR_DEFINED

#endif // !_UNICODE

/// \brief The C-library interface to Xecrets File Classic functions
/// This should be included within extern "C" if used from C++ as a DLL

#ifndef AXCL_CHUNK_SIZE
#define AXCL_CHUNK_SIZE (1*1024*1024)
#endif
#ifndef AXCL_ZIP_SAVE_RATIO
#define AXCL_ZIP_SAVE_RATIO 25
#endif
#ifndef AXCL_DEFAULT_WRAP_ITERATIONS
#define AXCL_DEFAULT_WRAP_ITERATIONS 20000
#endif

enum {
	AXCL_E_OK = 0,                          ///< No error - all is ok

	// Callback actions, called by the library at various times
	AXCL_A_PROGRESS = 100,                  ///< Report progress and check for cancel
	AXCL_A_GET_CIPHER_PATH,                 ///< You may display a SaveAs dialog (Out)
	AXCL_A_GET_PLAIN_PATH,                  ///< You may display a SaveAs dialog (Out)
	AXCL_A_TCHAR2ANSI,                      ///< Convert from TCHAR (possibly Unicode) to Ansi - possibly a null operation
	AXCL_A_ANSI2TCHAR,                      ///< Convert from Ansi to TCHAR (possibly Unicode) - possibly a null operation

	// Return status codes
	AXCL_E_INTERNAL = 900,                  ///< Internal error
	AXCL_E_NOTFOUND,                        ///< File not found
	AXCL_E_HMAC,                            ///< HMAC mismatch
	AXCL_E_BAD_VERSION,                     ///< Too new version
	AXCL_E_BAD_GUID,                        ///< Not an Xecrets File Classic file
	AXCL_E_ACCESS,                          ///< Some form of access error
	AXCL_E_CANCEL,                          ///< Cancel requested/performed
	AXCL_E_IGNORED,                         ///< Requested action/function ignored
	AXCL_E_XECRETSFILE,                         ///< Xecrets File Classic error
	AXCL_E_MEMORY,                          ///< Memory allocation error or similar
	AXCL_E_NOTYET,                          ///< Not Yet Implemented
	AXCL_E_BADOP,                           ///< Unknown operation requested
	AXCL_E_KEYNOTFOUND,                     ///< The key was not found in the cache
	AXCL_E_WRONGKEY,                        ///< This was not the correct key
};

/// \brief The universal callback
/// \param pParam the parameter-block provided on the original library call
/// \param iCallbackAction the operation requested
/// \param p A pointer to operation-dependent data, or NULL
/// \param cb The size of the operation-dependent data, if relevant
/// \param piResult Pointer to a location to store a result code, or NULL
/// \return An operation-dependent return value, or NULL if irrelevant or error
struct AXCL_PARAM_;
typedef const void* (*AXCL_CALLBACK)(const AXCL_PARAM_* pParam, int iCallbackAction, const void* p, size_t cb, int* piResult);

/// \brief Various buffer indices.
/// All of the buffers must be left to be managed by XecretsFileLib at all times.
enum {
	AXCL_STR_ERRORMSG,                      ///< OUT: Error message if any from a requested function
	AXCL_STR_PATHOUT,                       ///< IN/OUT: The full path to the destination file.
	AXCL_STR_FILENAME,                      ///< IN/OUT: The file name representation of the plain-text
	AXCL_STR_N                              ///< Last in list => Value == number of buffers
};

/// \brief A 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601, UTC.
/// A 100-nanosecond, is 1/10 of a microsecond - so 10 000 of these make up a millisecond, etc...
/// This is a Windows-inspired structure. Don't depend on long being exactly 32 bits (but it must be at least 32 bits)
typedef struct AXCL_FILETIME_ {
	unsigned long partLowDateTime;          /// low 32 bits
	unsigned long partHighDateTime;         /// high 32 bits
} AXCL_FILETIME;

enum {
	AXCL_FILETIME_CT,                       ///< Creation Time or zero if not applicable
	AXCL_FILETIME_LAT,                      ///< Last Access Time or zero if not applicable
	AXCL_FILETIME_LWT,                      ///< Last Write Time or zero of not applicable
	AXCL_FILETIME_N                         ///< Last in list => Value == number of buffers
};

enum {
	AXCL_KEY_ENC,                           ///< A Key Encrypting Key used for encryption
	AXCL_KEY_DEC,                           ///< A Key Encrypting Key used for decryption
	AXCL_KEY_N                              ///< Last in list => Value == number of keys
};

typedef struct AXCL_KEY_ {
	unsigned char* pKEK;                    ///< The raw, hashed, Key Encrypting Key
	size_t cbKEK;                           ///< The size of the raw, hashed, Key Encrypting Key
	unsigned char* pFingerprint;            ///< A non-secret fingerprint uniquely identifying the specific Key Encrypting Key
	size_t cbFingerprint;                   ///< The size of the fingerprint
} AXCL_KEY;

typedef struct AXCL_PARAM_ {
	int iResultCode;                        ///< The result of the most recent operation
	void* pCallbackContext;                 ///< The context to send to the callback
	void* pCacheContext;                    ///< An opaque reference to a cache of encryption keys
	AXCL_CALLBACK pfCallback;               ///< The callback
	_TCHAR* strBufs[AXCL_STR_N];
	AXCL_KEY keys[AXCL_KEY_N];
	AXCL_FILETIME ft[AXCL_FILETIME_N];      ///< Communicate file-times portably, sort of
	int iProgress;                          ///< Current progress percentage value 0 - 100
	int iZipMinSaveRatio;                   ///< Percentage needed to be removed by compression (for the first chunk) needed to do compression
	size_t cbChunkSize;                     ///< The byte chunk size we read and write in
} AXCL_PARAM;

/// \brief Allocate and initialize a parameter block
extern AXCL_PARAM* axcl_Open(AXCL_CALLBACK pfCallback, void* pContext);
/// \brief Hash a key, storing the result and fingerprint in the indicated key location in the parameter block
extern int axcl_HashKey(AXCL_PARAM* pParam, int iKeyType, const unsigned char* pPassphrase, size_t cbPassphrase, const _TCHAR* szKeyFullPath);
/// \brief Decrypt a file to plain-text, using the provided parameters
extern int axcl_DecryptFileData(AXCL_PARAM* pParam, int iKeyTypeDec, const _TCHAR* szCipherTextFullPath);
/// \brief Decrypt file meta-data, using the provided parameters, returning the data in the parameter block
extern int axcl_DecryptFileMeta(AXCL_PARAM* pParam, int iKeyTypeDec, const _TCHAR* szCipherTextFullPath);
/// \brief Encrypt a file, using the provided parameters
extern int axcl_EncryptFile(AXCL_PARAM* pParam, int iKeyTypeEnc, const _TCHAR* szPlainTextFullPath, const _TCHAR* szPlainTextFileName);
/// \brief Re-encrypt a file under a new key, using the provided parameters
extern int axcl_ReencryptFile(AXCL_PARAM* pParam, int iKeyTypeDec, int iKeyTypeEnc, const _TCHAR* szCipherTextFullPath);
/// \brief Free all memory resources associated with the provided parameter block
extern void axcl_Close(AXCL_PARAM* pParam);

/// \brief Allocate and initialize a new key-cache
extern void* axcl_CacheOpen();
/// \brief Store a key and it's fingerprint in the provided cache-object
extern int axcl_CacheStoreKey(AXCL_PARAM* pParam, int iKeyType, void* pCache);
/// \brief Load a key and it's fingerprint from the provided cache-object into the provided parameter block
extern int axcl_CacheLoadKey(AXCL_PARAM* pParam, int iKeyType, void* pCache, const unsigned char* pFingerprint, size_t cbFingerprint);
/// \brief Search for a key that decrypts the provided file, and load it and it's fingerprint into the provided parameter block
extern int axcl_CacheFindKey(AXCL_PARAM* pParam, int iKeyType, void* pCache, const _TCHAR* szInFullPath);
/// \brief Free all memory resources associated with the provided parameter block
extern void axcl_CacheClose(void* pCache);

#endif XECRETSFILELIB_H