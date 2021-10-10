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

<b> Install make using choco package manager for windows</b>
1. https://chocolatey.org/install

<b>GIT Installation</b>
1. https://git-scm.com/downloads
2. or, choco install git

<b>GoLang Installation</b>
1. https://golang.org/
2. or, choco install golang 

<b>Rust Compiler Installation</b>
1. https://www.rust-lang.org/tools/install
2. or, choco install rust

<b>Make Installation</b>
1. choco install make

<b>GCC Installation</b>
1. https://www.msys2.org/
2. From the windows start bar, search for "msys2 msys" and launch that to get a shell
3. from the shell, say 'pacman -S mingw-w64-x86_64-toolchain' - here I just select the install "all" option,
    we might  not want to install everything, TODO to figure that out later 
4. Assuming msys2 was installed in C:\msys64, add this system environment Path variable: C:\msys64\mingw64\bin
   (google for how to add to Path on windows)
5. The gcc/toolchain used to compile rust and the one used by go to compile cgo (to integrate rust agent with go)
   has to be the same toolchain or else it will produce linker errors. The cgo compilation/linking just picks stuff
   up from the Path variable, Rust has to be told where to pick up the tools from or else it will use the tools it
   installed itself. So add the below to make rust pick up the right toolchains we installed

   Open C:\Users\gopak\.cargo\config and add the below (gopak is my userid / homedirectory on windows, substitite with yours)

   [target.x86_64-pc-windows-gnu]
   linker = "C:\\msys64\\mingw64\\bin\\gcc.exe"
   ar = "C:\\msys64\\mingw64\\bin\\ar.exe"


<b>Reboot your computer</b>

<b>Build and run nxt-windows.exe</b>
1. Launch powershell as administrator
2. cd agent\rust\agent
3. .\build_windows.ps1
4. cd agent\rust\platforms\windows
5. .\build.bat
6. .\amd64\nxt-windows.exe nxt0
7. nxt0 adaptor can be seen here: Control Panel => Network and Internet => Network Connection

```$ route print

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.4.1     192.168.4.88     45
          0.0.0.0          0.0.0.0       10.82.31.4       10.82.31.5      5 <-- nxt-windows IP, lower metric is better
```
<b> Windows Installer XML (WiX) </b>
1. WiX toolset is an opensource MSI (Microsoft Installer) package generator
2. Go to https://wixtoolset.org/releases/, download Recommended Build. 
3. Extract the zip file to C:\SourceControl\WiX311\
4. Add this path to your system environment variable.
Ref: https://www.packtpub.com/product/wix-3-6-a-developer-s-guide-to-windows-installer-xml/9781782160427

<b> Install Nextensio Agent Console App using MSI </b>
1. nxt-win.wxs is the XML manifest file to create the agent's MSI package. Its an input to WiX. 
2. Run: .\build.bat msi, to generate the MSI package: dist\nextensio-{ARCH}.msi, where {ARCH} is amd64, etc.
3. From File Explorer, double clicking nextensio-{ARCH}.wxs. It will install all files into C:\Program Files\Nextensio & its corresponding start menu short-cut 
4. To update the agent version: Modify .\build.bat ProductVersion defined variable in the compiler 
5. To generate GUID, use PowerShell "New-Guid": https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-guid?view=powershell-7.1
6. After installation, Nextensio folder will be added as a short-cut to Startup Menu.

<b> Uninstall Nextensio Agent Console App </b>
1. To uninstall, go to Control Panel -> Programs -> Uninstall a program
2. Search for Nextensio Agent
3. Click 'Uninstall'
4. Note1: Because the product ID is fixed, everytime you need to install a new msi, you need to delete it first.
5. Note2: To workaround this, change Product Id in wxs to "*" to auto-generate the Product ID. Clean up later.


Miscellaneous Notes:

1. If you want to generate a "debug" version with console output, you can 
remove the "-H windowsgui" flag in build.bat and then the  version
that is built will pop up a console when the nextensio app is launched 