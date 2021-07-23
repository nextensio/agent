# nxt-windows

MS Power Shell Installation
1. Open Microsoft Store, search for PowerShell and Install.

MS Visual Studio Installation
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
9. Select Install
10. After installation is completed, sign-in to Visual Studio using your MS account.

MS Windows SDK Installation
1. Download Windows 10 SDK
   * https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/
2. Open winsdksetup.exe

Add signtool.exe path to your system environment variable. Signtool.exe comes with Windows SDK. It is located in C:\Program Files (x86)\Windows Kits\10\App Certification Kit. This link shows how you can add this path as System Path.
Example: https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/#:~:text=Click%20the%20%E2%80%9CEnvironment%20Variables%E2%80%A6%E2%80%9D%20button.%20Under%20the%20%E2%80%9CSystem,screen%20you%20can%20also%20edit%20or%20reorder%20them.

Create Self-Signed Certificate
1. Open PowerShell as administrator
2. New-SelfSignedCertificate -DNSName 'nextensio.net' -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert -Subject 'Nextensio Agent Windows Cert'
3. Copy the thumbprint ID to ./sign.bat
Example: https://sectigostore.com/page/how-do-i-generate-a-self-signed-code-signing-certificate/

MS Window Driver Kit Installation
1. Download WDK for Windows 10
   * https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
2. Downloads -> Other WDK downloads
3. Go to Step 2. Install the WDK, WDK Windows 10 version 2004.
4. Open wdksetup.exe and install it to this computer
5. Select, Install Windows Driver Kit Visual Studio extension and Install to Visual Studio Community 2019 (Visual Studio need to be shutdown for the installation to proceed)

GIT Installation
1. https://git-scm.com/downloads

GoLang Installation
https://golang.org/

Rust Compiler Installation
https://www.rust-lang.org/tools/install

Reboot your computer

Build and run nxt-windows.exe
1. Launch powershell as administrator
2. cd agent\rust\platforms\windows
3. ./build.bat
4. .\amd64\nxt-windows.exe nxt0
5. nxt0 adapator can be seen here: Control Panel => Network and Internet => Network Connection

```$ route print
; all traffic 0.0.0.0 route to 10.82.31.4, with metric 5 (preference)

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.4.1     192.168.4.88     45
          0.0.0.0          0.0.0.0       10.82.31.4       10.82.31.5      5 <-- nxt-windows IP
```