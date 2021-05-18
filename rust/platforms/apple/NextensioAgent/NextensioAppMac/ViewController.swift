//
//  ViewController.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 2/14/21.
//

import Cocoa
import NetworkExtension
import OktaOidc

class ViewController: AuthBaseViewController {
    
    // UI Constructs Declarations
    @IBOutlet weak var loginButton: NSButton!
    
    @IBOutlet weak var titleLabel: NSTextField!
    @IBOutlet weak var subtitleLabel: NSTextField!
    @IBOutlet weak var timezoneLabel: NSTextField!
    @IBOutlet weak var localeLabel: NSTextField!
    @IBOutlet weak var accessTokenLabel: NSTextField!
    @IBOutlet weak var refreshTokenLabel: NSTextField!
    
    @IBOutlet weak var accessTokenViewButton: NSButton!
    @IBOutlet weak var refreshTokenViewButton: NSButton!
    
    @IBOutlet weak var logoutButton: NSButton!
    @IBOutlet weak var connectButton: NSButton!
   
    @IBOutlet weak var connectDirectButton: NSButton!
    
    // Hard code VPN configurations
    let tunnelBundleId = "io.nextensio.agent1.tunnel"
    let dns = "8.8.8.8"
    
    var vpnInited = false
    var vpnDirect = false
    var userLogin = false
    
    // VPN Constructs
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        authFlowCoordinatorDelegate = AuthFlowCoordinator(with: self)
        
        // Default is vpnDirect
        vpnDirect = true
        initVPNTunnelProviderManager(directConn: vpnDirect)
    }
    
    override func shouldPerformSegue(withIdentifier identifier: String, sender: Any?) -> Bool {
        if (vpnDirect) {
            if (self.connectDirectButton.title == "Disconnect") {
                // vpnDirect is running, pop up error message.
                _ = self.showError(message: "Connect direct is on, disconnect first before logging in")
                return false
            }
        }
        return true
    }
    
    // OIDC Segue Declarations
    override func prepare(for segue: NSStoryboardSegue, sender: Any?) {
        print("calling prepare Segue")
        let signInView = segue.destinationController as! SignInViewController
        signInView.representedObject = self // may not be needed since we use delegate
        signInView.authFlowCoordinatorDelegate = authFlowCoordinatorDelegate
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        print("view did load")
        // OIDC setup - from okta.plist (will occur in the delegate)
        accessToken = ""
        refreshToken = ""
        idToken = ""
        // default state of buttons
        connectDirectButton.isEnabled = true
        loginButton.isEnabled = true
        connectButton.isEnabled = false
        logoutButton.isEnabled = false
    }
    
    override func viewWillDisappear() {
        super.viewWillDisappear();
        print("view will dissappear")
        self.vpnManager.connection.stopVPNTunnel()
        vpnInited = false
    }
    
    override func viewWillAppear() {
        super.viewWillAppear()
        print("view will appear")
    }
    
    @IBAction func logoutTapped(_ sender: Any) {
        print("ViewController.logoutTapped()")
        self.authFlowCoordinatorDelegate?.onLoggedOut()
    }
    
    override func loginUserProfile(title: String, subTitle: String, timeZone: String, locale: String, accessToken: Bool, refreshToken: Bool, stateManager: OktaOidcStateManager) {
        // Update user information
        titleLabel.stringValue = title
        subtitleLabel.stringValue = subTitle
        timezoneLabel.stringValue = timeZone
        localeLabel.stringValue = locale
        
        // Store Tokens in SecureStorage
        oidcStateManager = stateManager
        oidcStateManager?.writeToSecureStorage()
        print("ViewController.writeToSecureStorage")
        
        if accessToken {
            accessTokenLabel.stringValue = "YES"
            self.accessToken = oidcStateManager?.accessToken
        } else {
            accessTokenLabel.stringValue = "NO"
            self.accessToken = ""
        }
        
        if refreshToken {
            refreshTokenLabel.stringValue = "YES"
            self.refreshToken = oidcStateManager?.refreshToken
        } else {
            refreshTokenLabel.stringValue = "NO"
            self.refreshToken = ""
        }
        
        if let _ = oidcStateManager?.idToken {
            self.idToken = oidcStateManager?.idToken
        } else {
            self.idToken = ""
        }
        // VPN configuration setup
        initVPNTunnelProviderManager(directConn: false)
        // self?.viewTokensButton.isEnabled = true
        logoutButton.isEnabled = true
        loginButton.isEnabled = false
        userLogin = true
    }
    
    override func logoutUserProfile() {
        logoutButton.isEnabled = false

        titleLabel.stringValue = "Welcome"
        subtitleLabel.stringValue = "--"
        timezoneLabel.stringValue = "--"
        localeLabel.stringValue = "--"
        accessTokenLabel.stringValue = "NO"
        refreshTokenLabel.stringValue = "NO"

        accessToken = ""
        refreshToken = ""
        
        oidcStateManager = nil
        
        // Toggle VPN Button from Connect -> Disconnect
        self.vpnManager.connection.stopVPNTunnel()
    
        // reset configuration to directConn = true
        initVPNTunnelProviderManager(directConn: true)

        loginButton.isEnabled = true
        logoutButton.isEnabled = false
        userLogin = false
    }
    
    @IBAction func accessTokenViewTapped(_ sender: Any) {
    }
    
    @IBAction func refreshTokenViewTapped(_ sender: Any) {
    }

    private func initVPNTunnelProviderManager(directConn: Bool) {
        print("init vpn tunnel provider manager ..directConn = \(directConn)")
        NETunnelProviderManager.loadAllFromPreferences { (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
                print(error)
            }
            if let savedManagers = savedManagers {
                if savedManagers.count > 0 {
                    self.vpnManager = savedManagers[0]
                }
            }
            
            self.vpnManager.loadFromPreferences(completionHandler: { (error:Error?) in
                if let error = error {
                    print(error)
                }
                
                // Hard code VPN configurations
                let providerProtocol = NETunnelProviderProtocol()
                
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = [
                                                          "dns": self.dns,
                                                          "access": self.accessToken as Any,
                                                          "refresh": self.refreshToken as Any,
                                                          "id": self.idToken as Any,
                                                          "direct": directConn ? "true" : "false",
                                                          "highMem": true,
                ]
                providerProtocol.serverAddress = "127.0.0.1"
                self.vpnManager.protocolConfiguration = providerProtocol
                self.vpnManager.localizedDescription = "nextensio"
                self.vpnManager.isEnabled = true

                self.vpnManager.saveToPreferences(completionHandler: { (error:Error?) in
                    if let error = error {
                        print(error)
                    } else {
                        print("Save successfully")
                    }
                })
                self.VPNStatusDidChange(nil)
            })
        }
        
        if (vpnInited == false) {
            NotificationCenter.default.addObserver(self, selector: #selector(ViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
            vpnInited = true
        }
    }
    
    @objc func VPNStatusDidChange(_ notification: Notification?) {
        let status = self.vpnManager.connection.status
        switch status {
        case .connecting:
            print("vpn status connecting...vpnDirect = \(vpnDirect)")
            break
        case .connected:
            print("vpn status connected...vpnDirect = \(vpnDirect)")
            handleConnectButtons(status: true)
            break
        case .disconnecting:
            print("vpn status disconnecting...vpnDirect = \(vpnDirect)")
            break
        case .disconnected:
            print("vpn status disconnected...vpnDirect = \(vpnDirect)")
            handleConnectButtons(status: false)
            break
        case .invalid:
            print("vpn status invalid...vpnDirect = \(vpnDirect)")
            break
        case .reasserting:
            print("vpn status reasserting...vpnDirect = \(vpnDirect)")
            break
        @unknown default:
            break
        }
    }
    
    func handleConnectButtons(status: Bool) {
        if (vpnDirect) {
            if (status) {
                self.connectButton.isEnabled = false
                self.connectDirectButton.title = "Disconnect"
            } else {
                self.connectButton.isEnabled = true
                self.connectDirectButton.title = "Connect Direct"
            }
        } else {
            if (status) {
                connectDirectButton.isEnabled = false
                connectButton.title = "Disconnect"
            } else {
                connectDirectButton.isEnabled = true
                connectButton.title = "Connect"
            }
        }
    }

    @IBAction func connectDirect(_ sender: Any) {
        print("connectDirect pressed")
        if (userLogin) {
            _ = self.showError(message: "User logged in, connect direct function disabled")
            return
        }
        vpnDirect = true

        DispatchQueue.main.asyncAfter(deadline: .now(), execute: {
            let button = sender as! NSButton
            self.vpnManager.loadFromPreferences { (error:Error?) in
                if let error = error {
                    print(error)
                }
                if (button.title == "Connect Direct") {
                    do {
                        print("start vpn tunnel direct")
                        try self.vpnManager.connection.startVPNTunnel()
                    } catch {
                        print(error)
                    }
                } else {
                    print("stop vpn tunnel direct")
                    self.vpnManager.connection.stopVPNTunnel()
                }
            }
        })
    }
    
    @IBAction func connectTunnel(_ sender: Any) {
        print("connectTunnel pressed")
        if (!userLogin) {
            _ = self.showError(message: "No login user")
            return
        }
        vpnDirect = false

        let button = sender as! NSButton
        self.vpnManager.loadFromPreferences { (error:Error?) in
            if let error = error {
                print(error)
            }
            if (button.title == "Connect") {
                do {
                    try self.vpnManager.connection.startVPNTunnel()
                } catch {
                    print(error)
                }
            } else {
                self.vpnManager.connection.stopVPNTunnel()
            }
        }
    }
    
    private func dialogOKCancel(question: String, text: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = question
        alert.informativeText = text
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}
