@echo off
rem Nextensio Agent Windows

setlocal enabledelayedexpansion
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if "%1"=="msi" ( 
	set WIX_CANDLE_FLAGS=-nologo
    set WIX_LIGHT_FLAGS=-nologo -spdb
	call :msi amd64 x86_64 x64 || goto :error
	exit /b 0
)

if exist .deps\prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd .deps || goto :error
	call :download wintun.zip https://www.wintun.net/builds/wintun-0.12.zip eba90e26686ed86595ae0a6d4d3f4f022924b1758f5148a32a91c60cc6e604df || goto :error
	copy /y NUL prepared > NUL || goto :error
	set GOPRIVATE=gitlab.com
	set GO111MODULE=on
	go get gitlab.com/nextensio/common/go

	cd .. || goto :error

:build
	set GOOS=windows
	set GOARM=7
	if "%GoGenerate%"=="yes" (
		echo [+] Regenerating files
		go generate ./... || exit /b 1
	)
	call :build_plat amd64 x86_64 amd64 || goto :error

:sign
	if exist .\sign.bat call .\sign.bat
	if "%SigningCertificate%"=="" goto :success
	if "%TimestampServer%"=="" goto :success
	echo [+] Signing
	signtool sign /sha1 "%SigningCertificate%" /fd sha256 /tr "%TimestampServer%" /td sha256 /d nextensio.net amd64\nextensio.exe || goto :error

:success
	echo [+] Success. Launch nextensio.exe.
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
	del %~1\nextensio.exe
	set GOARCH=%~3
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	windres.exe -I ".deps\wintun\bin\%~1" -i resources.rc -o "resources_%~3.syso" -O coff -c 65001 || exit /b %errorlevel%
	echo [+] Building program %1
	go build -tags load_wintun_from_rsrc -x -v -trimpath -ldflags "-v -linkmode external -extldflags -static" -o "%~1\nextensio.exe" || exit /b 1
	goto :eof

:msi
	if not exist "%~1" mkdir "%~1"
	echo [+] wix compiling nxt-win.wxs
	candle %WIX_CANDLE_FLAGS% -dAGENT_PLAT="%~1" -dProductVersion="1.0.0" -o "%~1\nxt-win.wixobj" -arch %~3 nxt-win.wxs || goto :error
	echo [+] wix linking nxt-win-%~1.msi package
	light %WIX_LIGHT_FLAGS% -out "dist\nxt-win-%~1.msi" "%~1\nxt-win.wixobj" || goto :error
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%
