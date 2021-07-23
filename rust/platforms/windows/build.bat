@echo off
rem Nextensio Agent Windows

setlocal enabledelayedexpansion
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps\llvm-mingw\bin;%BUILDDIR%.deps\go\bin;%BUILDDIR%.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	rem Download GOLANG
	call :download go.zip https://download.wireguard.com/windows-toolchain/distfiles/go1.17beta1-windows_amd64_2021-06-11.zip 09601956a35ee4c2fa199da301c4b210fd365a46d286a7160388a1cdc07b7a6d || goto :error
	rem Mirror of https://github.com/mstorsjo/llvm-mingw/releases/download/20201020/llvm-mingw-20201020-msvcrt-x86_64.zip
	call :download llvm-mingw-msvcrt.zip https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20201020-msvcrt-x86_64.zip 2e46593245090df96d15e360e092f0b62b97e93866e0162dca7f93b16722b844 || goto :error
	rem Mirror of https://sourceforge.net/projects/ezwinports/files/make-4.2.1-without-guile-w32-bin.zip
	call :download make.zip https://download.wireguard.com/windows-toolchain/distfiles/make-4.2.1-without-guile-w32-bin.zip 30641be9602712be76212b99df7209f4f8f518ba764cf564262bc9d6e4047cc7 "--strip-components 1 bin" || goto :error
	call :download wireguard-tools.zip https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-1.0.20210223.zip c0cee24d469ecd3f0420dd2cc9747faa67f257a39c17063c10cff99ba62a6fa6 "--exclude wg-quick --strip-components 1" || goto :error
	call :download wintun.zip https://www.wintun.net/builds/wintun-0.12.zip eba90e26686ed86595ae0a6d4d3f4f022924b1758f5148a32a91c60cc6e604df || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	set GOOS=windows
	set GOARM=7
	set GOPATH=%BUILDDIR%.deps\gopath
	set GOROOT=%BUILDDIR%.deps\go
	if "%GoGenerate%"=="yes" (
		echo [+] Regenerating files
		go generate ./... || exit /b 1
	)
	call :build_plat amd64 x86_64 || goto :error

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d nextensio.net amd64\nxt-windows.exe || goto :error

:success
	echo [+] Success. Launch nxt-windows.exe.
	exit /b 0

:download
	echo [+] Downloading %1
	curl -#fLo %1 %2 || exit /b 1
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	echo [+] Extracting %1
	tar -xf %1 %~4 || exit /b 1
	echo [+] Cleaning up %1
	del %1 || exit /b 1
	goto :eof

:build_plat
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	%~2-w64-mingw32-windres -I ".deps\wintun\bin\%~1" -i resources.rc -o "resources_%~3.syso" -O coff -c 65001 || exit /b %errorlevel%
	echo [+] Building program %1
	go build -tags load_wintun_from_rsrc -v -trimpath -o "%~1\nxt-windows.exe" || exit /b 1
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
