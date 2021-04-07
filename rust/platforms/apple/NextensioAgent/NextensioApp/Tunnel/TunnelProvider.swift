//
//  TunnelProvider.swift
//  NextensioApp
//
//  Created by Rudy Zulkarnain on 4/5/21.
//

import UIKit
import Foundation
import OktaOidc
import NetworkExtension

class TunnelProvider {
    
    weak var connectButton: UIButton!
    var tunnelManager: NETunnelProviderManager = NETunnelProviderManager()
    
    // Hard code VPN configurations
    let tunnelBundleId = "com.nextensio.io.vpn.NextensioApp.NextensioPacketTunnel"
    let serverAddress = "127.0.0.1"
    let serverPort = "8080"
    let mtu = "1500"
    let ip = "169.254.2.1"
    let subnet = "255.255.255.0"
    let dns = "8.8.8.8"
    
    init(button: UIButton, state: OktaOidcStateManager?) {
        connectButton = button
        initTunnelProviderManager(state: state)
    }

    private func initTunnelProviderManager(state: OktaOidcStateManager?) {
        NETunnelProviderManager.loadAllFromPreferences { (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
                print(error)
            }
            if let savedManagers = savedManagers {
                if savedManagers.count > 0 {
                    self.tunnelManager = savedManagers[0]
                }
            }

            self.tunnelManager.loadFromPreferences(completionHandler: { (error:Error?) in
                if let error = error {
                    print(error)
                }
                
                var accessToken = ""
                var refreshToken = ""
                var idToken = ""
                
                if (state != nil) {
                    accessToken = state?.accessToken ?? ""
                    refreshToken = state?.refreshToken ?? ""
                    idToken = state?.idToken ?? ""
                }

                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = ["port": self.serverPort,
                                        "server": self.serverAddress,
                                        "ip": self.ip,
                                        "subnet": self.subnet,
                                        "mtu": self.mtu,
                                        "dns": self.dns,
                                        "access": accessToken,
                                        "refresh": refreshToken,
                                        "id": idToken
                ]
                providerProtocol.serverAddress = self.serverAddress
                
                self.tunnelManager.protocolConfiguration = providerProtocol
                self.tunnelManager.localizedDescription = "nextensio"
                self.tunnelManager.isEnabled = true
                self.tunnelManager.saveToPreferences(completionHandler: { (error:Error?) in
                    if let error = error {
                        print(error)
                    } else {
                        print("Save successfully")
                    }
                })
                self.VPNStatusDidChange(nil)
            })
        }
        
        NotificationCenter.default.addObserver(self, selector: #selector(TunnelProvider.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
    }

    @objc func VPNStatusDidChange(_ notification: Notification?) {
        print("VPN Status changed:")
        let status = self.tunnelManager.connection.status
        switch status {
        case .connecting:
            print("Connecting...")
            connectButton.setTitle("Disconnect", for: .normal)
            break
        case .connected:
            print("Connected...")
            connectButton.setTitle("Disconnect", for: .normal)
            break
        case .disconnecting:
            print("Disconnecting...")
            break
        case .disconnected:
            print("Disconnected...")
            connectButton.setTitle("Connect", for: .normal)
            break
        case .invalid:
            print("Invalid")
            break
        case .reasserting:
            print("Reasserting...")
            break
        @unknown default:
            break
        }
    }

    func connectDirect() {
        print("connect direct")
                
        self.tunnelManager.loadFromPreferences { (error:Error?) in
            if let error = error {
                print(error)
            }
            do {
                try self.tunnelManager.connection.startVPNTunnel()
            } catch {
                print(error)
            }
        }
    }
    
    func disconnectDirect() {
        print("disconnect direct")
                
        self.tunnelManager.loadFromPreferences { (error:Error?) in
            if let error = error {
                print(error)
            }
            self.tunnelManager.connection.stopVPNTunnel()
        }
    }
    
}
