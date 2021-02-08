# Nextensio MacOS/iOS tunnel app

## Pre-requisite 

- An apple device (ex. macbook-pro)
- Apple Developer License $99/year for individual (register with developer.apple.com or buy enterprise license for multiple users)
- Download xcode latest from Apple App Store 

## Apple Developer License

- Register your apple developer account through Xcode preferences -> Account
- Open app/nxtapp.xcodeproj file, go to nxtapp and nxtTunnel targets -> Sign & Capabilities to change the respective Team in order to build the apps with Network Extension successfully

## Xcode Scheme 

- Xcode Scheme defines a collection of target to build. You can pick "My Mac" for MacOS or "iPhone X" for iOS build. 

## Two Processes and files

- nxtapp - is the main app responsible for the storyboard (aka UI), system configuration and tunnel on/off trigger
- nxtTunnel - is the tunnel provider process to handle tunnel packet flow. Main functions are startTunnel() and stopTunnel()
- ViewController.swift and PacketProviderTunnel.swift are the two main files that handle the configuration and packet flow
- Two methods to connect to local agent, 1. through exposing tun fd and WG adaptor, 2. Socket.swift is a raw socket class to connect to local agent (this is WIP)
