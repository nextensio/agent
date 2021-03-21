# Nextensio MacOS/iOS tunnel app

## Pre-requisite 

- An apple device (ex. macbook-pro)
- Apple Developer License $99/year for individual (register with developer.apple.com or buy enterprise license for multiple users)
- Download xcode latest from Apple App Store 
- iOS version 13.0 and above
- MacOS version 11.1 and above
- Install cocoapod: https://cocoapods.org/

## Apple Developer License

- Register your apple developer account through Xcode preferences -> Account
- Open NextensioAgent.xcodeproj file, go to nxtapp and nxtTunnel targets -> Sign & Capabilities to change the respective Team in order to build the apps with Network Extension successfully

## Okta SDK Installation 

- Podfile: CocoaPod configuration to download OktaAuth/JWT/OIDC
 
- For RUST agent:
- $ cd rust/platforms/apple
- $ pod install
 
- For GO agent:
- $ cd go/platforms/apple
- $ pod install
-
- This creates new xcode workspace file

## Load XCode

- Open NextensioAgent.xcworkspace (don't use NextensioAgent.xcodeproj)

## Building iOS target in Xcode

- For RUST agent:
- build Target:NextensioRustBridge, pick iPhone (simulator/device) to generate libnextensioIOS.a 
- build Target:NextensioApp, pick iPhone (simulator/device) to generate the NextensioAgent app and NextensioPacketTunnel appex

- For GO agent:
- build Target:NextensioGoBridgeIOS, pick iPhone (simulator/device) to generate libnxt.a 
- build Target:NextensioApp, pick iPhone (simulator/device) to generate the NextensioAgent app and NextensioPacketTunnel appex

## Building MacOS target in Xcode

- For RUST agent:
- build Target:NextensioRustBridge, pick My Mac to generate libnextensioMacOSX.a 
- build Target:NextensioApp, pick My Mac to generate the NextensioAgent app and NextensioPacketTunnel appex

- For GO agent:
- build Target:NextensioGoBridgeMacOSX, pick My Mac to generate libnxt.a 
- build Target:NextensioAppMacOSX, pick My Mac to generate the NextensioAgentAppMacOSX app and NextensioPacketTunnelMacOS appex

## Source Code Groups

- NextensioApp: the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioAppMacOSX: macosx main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioPacketTunnel: the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- NextensioRustBridge: the RUST glue code for the agent
- NextensioGoBridge: the GO glue code for the agent

## Connection 

- Direct to internet (default): direct variable set to 1 in initNextensioAgent() and seconds var to 1.0 in startTunnel
- Via nextensio cloud: change direct var from 1 to 0 in initNextensioAgent() and seconds var to 30.0 in startTunnel

## Rust adaptation (Installation)

- install rust: $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
- install cbindgen, to generate C headerfile for swift: $ cargo install --force cbindgen
- if needed to re-generate the C headerfile: $ cbindgen -l C -o nxt-api.h
- source env: $ source $HOME/.cargo/env
- add ios/macos targets: $ rustup target add aarch64-apple-ios x86_64-apple-ios x86_64-apple-darwin
- check its working: $ rustup show
- add: $HOME/.cargo/config: [net]
                            git-fetch-with-cli = true
