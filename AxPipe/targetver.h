#pragma once

// When AxPipe is made portable, this Windows-stuff must be moved out of here. It's here right now
// to enable code that uses AxPipe to "appear" portable, in that that code at least does not need to
// define and include all this.

// The following macros define the minimum required platform.  The minimum required platform
// is the earliest version of Windows, Internet Explorer etc. that has the necessary features to run 
// your application.  The macros work by enabling all features available on platform versions up to and 
// including the version specified.

// Modify the following defines if you have to target a platform prior to the ones specified below.
// Refer to MSDN for the latest info on corresponding values for different platforms.
#ifndef WINVER
#define WINVER 0x0501           // Allow use of features specific to Windows XP, Windows Server 2003 or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501     // Allow use of features specific to Windows XP, Windows Server 2003 or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0550        // Specifies that the minimum required platform is Internet Explorer 5.5.
#endif

