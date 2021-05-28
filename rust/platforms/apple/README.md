# Nextensio MacOS/iOS tunnel app

## Pre-requisite 

- An apple device (ex. macbook-pro)
- Apple Developer License $99/year for individual (register with developer.apple.com or buy enterprise license for multiple users)
- Download xcode latest from Apple App Store 
- iOS version 12.3 and above
- MacOS version 11.1 and above
- Install cocoapod: https://cocoapods.org/

## Install OKTA SDK Installation 

- Podfile: CocoaPod configuration to download OktaAuth/JWT/OIDC
- For RUST agent:
``` 
$ cd rust/platforms/apple
$ pod install
``` 
- This installs download OktaAuthSdk, OktaJWT, OktaOidc and create NextensioAgent.xcworkspace file

## Run XCode

- Open XCode App, open a project of file
- For RUST agent, pick rust/platforms/apple/NextensioAgent.xcworkspace. 
- Don't use NextensioAgent.xcodeproj

## Apple Developer License

- Register your apple developer account through Xcode preferences -> Account
- Go to NextensioAgent -> TARGETS -> NextensioAppMac -> Sign & Capabilities -> change to respective Team  with the apple developer license in order to build the apps with Network Extension successfully
- Do the same for TARGETS: NextensioPacketTunnelMac, NextensioApp, NextensioPacketTunnel

## Building NextensioApp (iOS target) in Xcode

- Go to NextensioApp and NextensioPacketTunnel Targets, Build Phases -> Copy Bundle Bundle Resources -> remove Info.Plist, this is added when you do 'pod install'. For some reason, its a duplicate, xcode compilation doesn't like it.

- For RUST agent (warning: rust compilation is slow):
```
build Target:NextensioRustBridge, pick My Mac to generate libnextensioIOS.a (My Mac picked for x86_64 simulator & ARM64 devices) (use CMD-b)
build Target:NextensioApp, pick iPhone (an iPhone/iPad device) to generate the NextensioAgent app and NextensioPacketTunnel appex
```

- For GO agent:
```
build Target:NextensioGoBridge, pick iPhone (simulator/device) to generate libnxt.a 
build Target:NextensioApp, pick iPhone (simulator/device) to generate the NextensioAgent app and NextensioPacketTunnel appex
```

## Building NextensioAppMac (MacOS target) in Xcode

- WARNING: Only support X86 architecture, not M1
- For RUST agent (warning: rust compilation is slow):
```
build Target:NextensioRustBridgeMac, pick My Mac to generate libnextensioMacOSX.a 
build Target:NextensioAppMac, pick My Mac to generate the NextensioAgent app and NextensioPacketTunnel appex
```

- For GO agent:
```
build Target:NextensioGoBridgeMacOSX, pick My Mac to generate libnxt.a 
build Target:NextensioAppMacOSX, pick My Mac to generate the NextensioAgentAppMacOSX app and NextensioPacketTunnelMacOS appex
```

## To distribute IOS target

- Go to appstoreconnect.apple.com -> MyApps -> Testflights
- In XCode -> NextensioApp -> Signing & Capabilities -> pick Automatically Managed Signing 
- In XCode -> NextensioPacketTunnel -> Signing & Capabilities -> pick Automatically Managed Signing 
- In XCode -> Product -> Archive -> Distribute App -> App Store Connect

## To distribute MacOS target

- Distribution with Developer ID doesn't work with NetworkExtension
- Alternatively, need to distribute with Mac Developer license. This requires each Device UUID to be registered in the developer.apple.com account. Yes, each device that wants to run this app need to have their UUID registered.
- Change the version in NextensioApp Target -> General; NextensioPacketTunnelMac Target -> General
- Generate NextensioAppMac profile using io.nextension.agent bundle id. Pick "Mac Developer license". 
- Generate NextensioPacketTunnelMac profile using io.nextensio.agent.tunnel bundle id. Pick "Mac Developer license"
- Download the 2 profiles to your Download directory
- In XCode -> NextensioAppMac -> Signing & Capabilities -> uncheck Automatically Managed Signing -> import the NextensioAppMac profile just downloaded
- In XCode -> NextensioPacketTunnelMac -> Signing & Capabilities -> uncheck Automatically Managed Signing -> import the NextensioPacketTunnelMac profile you just downloaded 
- In XCode -> Product -> Archive -> Distribute App -> Development -> Import the right profiles -> Export 
- tar and gzip the exported directory to google drive for download

## Source Code Groups

- NextensioApp: the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioAppMacOSX: macosx main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioPacketTunnel: the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- NextensioRustBridge: the RUST glue code for the agent
- NextensioGoBridge: the GO glue code for the agent

## Connection 

- Direct to internet (default): direct variable set to 1 in initNextensioAgent() and seconds var to 1.0 in startTunnel
- Via nextensio cloud: change direct var from 1 to 0 in initNextensioAgent() and seconds var to 30.0 in startTunnel

## Rust adaptation (environment)

```
install rust: $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
install cbindgen, to generate C headerfile for swift: $ cargo install --force cbindgen
if needed to re-generate the C headerfile: $ cbindgen -l C -o nxt-api.h
source env: $ source $HOME/.cargo/env
add ios/macos targets: $ rustup target add aarch64-apple-ios x86_64-apple-ios x86_64-apple-darwin
check its working: $ rustup show
add: $HOME/.cargo/config: [net]
git-fetch-with-cli = true
```

## Code signing 

There are two ways by which we do code signing - one way for ios and one for macos. For ios, we have 
set the Signin&Capabilities as we can see to Autosign - apple takes care of signing and certificates
and all that. And then we distribute the ios software (Project-->Archive) using "AppStore" but not 
publishing it etc.. (for that we need to be a proper company), we just keep the software in TestFlight
which is a way to test pre-publish stage software. And in test flight we can invite others to try out
our test software if others also install test flight app on their ios devices

For macos, we use "Developer ID" + Notarization mechanism - ie we do Project-->Archive and then upload
the image to apple as "Developer ID" option and also ask apple to Notarize it. The Nextensio.app that
we get when we archive it can be sent to anyone as a zip file for example (after we get a mail from 
apple saying that notarization is succesful). People who get that zip file has to unzip it and 
MOVE the Nextensio.app TO /Applications folder - this step is VERY important, without moving it to
/Applications it wont work. On macos once we launch the software, it will ask us to go to system 
preferences --> Security and Allow what is called a "system extension" - this happens one time. For
the first time we also have to allow VPN service. After these two allows are done, then we can sign in
and use the app.

The way we have setup the build right now is using individual apple developer accounts. So if another
developer wants to build it on their laptop, when they sign in as themselves (in signin&capabilities),
that will also change all the xcode project files with the new "TEAM ID" - team id getting changed is
all right, but the issue is that the two "bundle ids" representing the app io.nextensio.agent1 and
io.nextensio.agent1.tunnel are both registered to that developer account. So you wil have to change
the bundle id to say io.nextensio.agent2 and io.nextensio.agent2.tunnel or something like that and then
search and replace ALL THE FILES in platforms/apple to replace former by latter. It also needs corresponding
profiles in the developer's apple account, more about profiles below

## Using the app

The app has just a Sign in and Sigout button. If Sign In is succesful using your nextensio username
and password, the button changes to "signout". Once Sign in is succesful, we automatically start
the VPN to send traffic to nextensio. Clicking Signout will terminate the VPN.

## On profiles

Profiles in apple control what capabilities an app has - like whether it can write to the file system,
whether it can use the camera etc.. There is a profile per app, ie a profile per 'bundle id' - as we
discussed earlier, each app has a bundle id (two apps in our case - the UI io.nextensio.agent1 and
the packet tunnel io.nextensio.agent1.tunnel). And the profile starts with inheriting some stuff from
the properties of the bundle itself, so its important to set the right properties for the bundle when
you create one

Note that since for ipad we are using the Auto Signing mechanism, ios automatically creates profiles
for these bundles, so the profiles below are purely applicable to macos. And these profiles are created
for macos selecting the "developer id" option - ie we want these profiles to be used to create images
which can be distributed as zip files to anyone

1. There needs to be an "app group" with some name - for example I name it as group.io.nextensio.agent1
   Both the UI and packet tunnel profiles are put as belonging to the same group. Google on how to 
   create an app group (and everything else below) in developer.apple.com

2. The UI app io.nextensio.agent1 needs to have the app group item checked with the group above selected,
   the Network Extension checked and System Extensio checked

3. The Packet tunnel app needs to have the app group item checked with the group above selected, the
   Network Extension checked - the system extension is NOT checked.

Other than whats mentioned above, nothing else in the profile is checked for either bundles

The next thing which will happen as part of creating a profile is creating a certificate which is needed
to sign the developer id images we build. I tried creating certificates in developer.apple.com alongside
creation of profiles, and I tried to download and install that in my mac (mac xcode needs it to sign the
images it builds), but that certificate just would not install in keychain for some reason. So I had to
instead create a certificate in Xcode (google for how to) and then ask xcode to upload it to developer.apple.com.
This way the certificate is already available to xcode without us having to download etc.. And once xcode
uploads the cert, it will pop up in developer.apple.com - and when you create a profile, select this 
certificate


