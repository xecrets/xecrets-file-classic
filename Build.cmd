call "%VSINSTALLDIR%vc\Auxiliary\Build\vcvarsall" x86
MSBuild AxCrypt.sln /p:Configuration=Debug;Platform=Win32
MSBuild AxCrypt.sln /p:Configuration=Release;Platform=Win32
call "%VSINSTALLDIR%vc\Auxiliary\Build\vcvarsall" amd64
MSBuild AxCrypt.sln /p:Configuration=Debug;Platform=x64
MSBuild AxCrypt.sln /p:Configuration=Release;Platform=x64