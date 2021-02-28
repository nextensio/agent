# Nextensio MacOS/iOS tunnel app

## Pre-requisite 

- An apple device (ex. macbook-pro)
- Apple Developer License $99/year for individual (register with developer.apple.com or buy enterprise license for multiple users)
- Download xcode latest from Apple App Store 
- iOS version 13.0 and above
- MacOS version 11.1 and above

## Apple Developer License

- Register your apple developer account through Xcode preferences -> Account
- Open NextensioAgent.xcodeproj file, go to nxtapp and nxtTunnel targets -> Sign & Capabilities to change the respective Team in order to build the apps with Network Extension successfully

## Building iOS target in Xcode

- iOS build
- First: build Target:NextensioGoBridgeIOS and pick iPhone X (simulator/device) to generate libnxt-go.a 
- Second: build Target:NextensioApp and pick iPhone X (simulator/device) to generate the NextensioAgent app
- (if second step doesn't generate PacketTunnel appex, go to third step and re-do second step)
- Third: build Target:NextensioPacketTunnel and pick iPhone X (simulator/device) to generate the NextensioPacketTunnel appex

## Building MacOS target in Xcode

- MacOS build
- First: build Target:NextensioGoBridgeMacOSX and pick my mac to generate libnxt-go.a 
- Second: build Target:NextensioAppMacOSX and pick my mac to generate the NextensioAgentAppMacOSX app
- (if second step doesn't generate PacketTunnel appex, go to third step and re-do second step)
- Third: build Target:NextensioPacketTunnelMacOSX and pick my mac to generate the NextensioPacketTunnel appex

## Source Code 

- NextensioApp - is the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioAppMacOSX - is the macosx main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioPacketTunnel - is the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- NextensioGoBridge - is the go glue code for the agent
- Files ViewController.swift and PacketProviderTunnel.swift are the two main files that handle the configuration and packet flow

## Connection

- To connect to nextensio -- change direct var from 1 to 0 in initNextensioAgent() and seconds var to 30.0 in startTunnel
- To connect to internet directly -- change direct var from 0 to 1 in initNextensioAgent() and seconds var to 0.0 in startTunnel
- Comming soon: login to okta/IDP to avoid tweaking the seconds var
