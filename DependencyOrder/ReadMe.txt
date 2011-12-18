This project is only here to fix an issue with MSBUild / Visual Studio dependency ordering
of projects.

We have AxDecrypt which references AxCryptCommon which references AxCryptMessages.

AxCryptMessages must be built before AxCryptCommmon, becuase it produces the AxCryptTexts.h
header file, needed by AxCryptCommon.

The problem is that if we reference AxCryptMessages from AxCryptCommon, then Visual Studio or MSBuild
get's the brilliant idea that it must add 'AxCryptMessages.lib' to the linkage of AxDecrypt. There is
no AxCryptMessages.lib since it's a dll. I could not find a way to get it to do this right.

The solution was to have AxCryptCommon reference this dummy project (which is an .exe, not a .lib) and
then have this project reference AxCryptMessages.

This appears to work from Visual Studio and MSBuild command line.

Just ignore the executable output.

(TODO - Remove the dependency on AxCryptMessages from AxCryptCommon - it won't work anyway since we
don't distribute AxCryptMessages with AxDecrypt....)
