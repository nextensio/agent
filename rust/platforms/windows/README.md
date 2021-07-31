# nxt-windows installations, building and running

<b>MS Power Shell Installation</b>
1. Open Microsoft Store, search for PowerShell and Install.

<b>MS Visual Studio Installation</b>
1. Download Microsoft Visual Studio 2019 Community Edition
   * https://visualstudio.microsoft.com/downloads/
2. Open Visual Windows Installer
3. Select Available tab
   * Install Visual Studio Community 2019 16.10.4
5. Select Workloads tab
   * Select Universal Windows Platform Development
   * Desktop development with C++
7. Select Individual components tab
   * C++ MFC for latest v142 build tools with Spectre Mitigations (x86 & x64)
   * C++ V14.29 (16.10) MFC for v142 build tools with Spectre Mitigatios (x86 & x64)
   * C++/CLI support for v142 build tools (Latest)
9. Select Install
10. After installation is completed, sign-in to Visual Studio using your MS account.

<b>MS Windows SDK Installation</b>
1. Download Windows 10 SDK
   * https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/
2. Open winsdksetup.exe

<b>Add signtool.exe path to your system environment variable</b> 
1. Signtool.exe comes with Windows SDK. It is located in C:\Program Files (x86)\Windows Kits\10\App Certification Kit. 2. This link shows how you can add this path as System variable Path: https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/#:~:text=Click%20the%20%E2%80%9CEnvironment%20Variables%E2%80%A6%E2%80%9D%20button.%20Under%20the%20%E2%80%9CSystem,screen%20you%20can%20also%20edit%20or%20reorder%20them.
3. add the path shown in step 1

<b>Create Self-Signed CodeSign Certificate</b>
1. Open PowerShell as administrator
2. New-SelfSignedCertificate -DNSName 'nextensio.net' -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject 'Nextensio Agent Windows Cert'
3. Copy the thumbprint ID to ./sign.bat
4. Example: https://sectigostore.com/page/how-do-i-generate-a-self-signed-code-signing-certificate/

<b>MS Windows Driver Kit (WDK) Installation</b>
1. Download WDK for Windows 10
   * https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Downloads -> Other WDK downloads
3. Go to Step 2. Install the WDK, WDK Windows 10 version 2004.
4. Open wdksetup.exe and install it to this computer
5. Select, Install Windows Driver Kit Visual Studio extension and Install to Visual Studio Community 2019 (Visual Studio need to be shutdown for the installation to proceed)

<b>GIT Installation</b>
1. https://git-scm.com/downloads

<b>GoLang Installation</b>
1. https://golang.org/

<b>Rust Compiler Installation</b>
1. https://www.rust-lang.org/tools/install

<b>MinGW | Minimalist GNU for Windows (gcc compiler)</b>
1. https://sourceforge.net/projects/mingw/
2. PS C:\MinGW\bin> ./mingw-get install gcc
3. PS C:\MinGW\bin> ./mingw-get install g++
4. add C:\MingGW\bin to your system PATH environment variable

<b>Reboot your computer</b>

<b>Build and run nxt-windows.exe</b>
1. Launch powershell as administrator
2. cd agent\rust\platforms\windows
3. ./build.bat
4. .\amd64\nxt-windows.exe nxt0
5. nxt0 adaptor can be seen here: Control Panel => Network and Internet => Network Connection

```$ route print

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.4.1     192.168.4.88     45
          0.0.0.0          0.0.0.0       10.82.31.4       10.82.31.5      5 <-- nxt-windows IP, lower metric is better
```

<b> Todo </b>
1. Integrate with Rust. nxt-api.h implementation. cgo build and Makefile.
2. Experiment with tun's FD. tun.NativeTunDevice is an interface. We need access to wintun.Adapter.
3. OKTA IDP integration for access token
4. Installation to 3rd party computers
5. Optimize Makefile, to avoid downloading golang, llvm, etc. Instead use system's installation.
6. Develop a GUI

```
type Adapter struct {
	handle uintptr
}

type NativeTun struct {
	wt        *wintun.Adapter <-- possible FD to pass into rust agent
	handle    windows.Handle
	rate      rateJuggler
	session   wintun.Session
	readWait  windows.Handle
	events    chan Event
	running   sync.WaitGroup
	closeOnce sync.Once
	close     int32
	forcedMTU int
}```