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

- Podfile: Okta SDK uses CocoaPod for installation
- platforms/apple $ pod install --> will download OktaAuth, OktaJWT and OktaOIDC and create new xcode workspace file

## XCode Workspace

- Open NextensioAgent.xcworkspace (don't use NextensioAgent.xcodeproj)

## Building iOS target in Xcode

- iOS build
- First: build Target:NextensioGoBridgeIOS and pick iPhone X (simulator/device) to generate libnxt.a 
- Second: build Target:NextensioApp and pick iPhone X (simulator/device) to generate the NextensioAgent app
- (if second step doesn't generate PacketTunnel appex, go to third step and re-do second step)
- Third: build Target:NextensioPacketTunnel and pick iPhone X (simulator/device) to generate the NextensioPacketTunnel appex

## Building MacOS target in Xcode

- MacOS build
- First: build Target:NextensioGoBridgeMacOSX and pick my mac to generate libnxt.a 
- Second: build Target:NextensioAppMacOSX and pick my mac to generate the NextensioAgentAppMacOSX app
- (if second step doesn't generate PacketTunnel appex, go to third step and re-do second step)
- Third: build Target:NextensioPacketTunnelMacOSX and pick my mac to generate the NextensioPacketTunnel appex

## Source Code 

- NextensioApp - is the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioAppMacOSX - is the macosx main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioPacketTunnel - is the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- NextensioGoBridge - is the go glue code for the agent
- Files ViewController.swift and PacketProviderTunnel.swift are the two main files that handle the configuration and packet flow

## Connect 

- By default, the code will connect directly to internet -- direct variable set to 1 in initNextensioAgent() and seconds var to 1.0 in startTunnel
- To connect to nextensio -- change direct var from 1 to 0 in initNextensioAgent() and seconds var to 30.0 in startTunnel

## Todo
- Future: Use Nextensio IDP login and password, pass accessToken to gateway

## Rust adaptation

1.  install rust: $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
                  $ cargo install --force cbindgen
2.  source env: $ source $HOME/.cargo/env
3.  add ios/macos targets: $ rustup target add aarch64-apple-ios x86_64-apple-ios x86_64-apple-darwin
4.  check its working: $ rustup show
5.  go to agent directory: $ cd agent/rust/agent
6.  add: ~/.cargo/config: [net]
                          git-fetch-with-cli = true
7.  build ios for device: $ cargo build --target aarch64-apple-ios --release
8.  build ios for simulator: $ cargo build --target x86_64-apple-ios --release
9.  build ios for macosx: $ cargo build --target x86_64-apple-darwin --release
10.  archive all into one package: $ lipo -create target/aarch64-apple-ios/release/libnextensio.a target/x86_64-apple-ios/release/libnextensio.a target/x86_64-apple-darwin/release/libnextensio.a
11. check the library: $ lipo -info target/libnextensio.a
