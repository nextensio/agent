# Nextensio MacOS/iOS tunnel app

## Pre-requisite 

- An apple device (ex. macbook-pro)
- Apple Developer License $99/year for individual (register with developer.apple.com or buy enterprise license for multiple users)
- Download xcode latest from Apple App Store 
- iOS version 13.0 and above
- MacOS version 10.15.1 and above

## Apple Developer License

- Register your apple developer account through Xcode preferences -> Account
- Open NextensioAgent.xcodeproj file, go to nxtapp and nxtTunnel targets -> Sign & Capabilities to change the respective Team in order to build the apps with Network Extension successfully

## Building iOS target in Xcode

- iOS build
- First: build Target:NextensioGoBridgeIOS to generate libnxt-go.a in relative build products
- Second: pick iPhone X (simulator) as the build target
- Third: build Target:NextensioApp to build the phone app and NextsionPacketTunnel

## Building MacOS target in Xcode

- WIP

## Two Processes and files

- NextensioApp - is the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- NextensioPacketTunnel - is the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- NextensioGoBridge - is the go glue code for the agent
- Files ViewController.swift and PacketProviderTunnel.swift are the two main files that handle the configuration and packet flow
- Two methods to connect to local agent, 1. through exposing tun fd and WG adaptor, 2. Socket.swift is a raw socket class to connect to local agent (this is WIP)
