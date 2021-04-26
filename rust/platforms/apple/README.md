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
- For GO agent:
``` 
$ cd go/platforms/apple
$ pod install
``` 
 
- This installs download OktaAuthSdk, OktaJWT, OktaOidc and create NextensioAgent.xcworkspace file

## Run XCode

- Open XCode App, open a project of file
- For RUST agent, pick rust/platforms/apple/NextensioAgent.xcworkspace. 
- For GO agent, pick go/platforms/apple/NextensioAgent.xcworkspace
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
