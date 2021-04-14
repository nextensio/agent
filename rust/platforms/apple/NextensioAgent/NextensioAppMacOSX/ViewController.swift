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
    
    var vpnInited = false
    var vpnDirect = false
    
    // VPN Constructs
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        authFlowCoordinatorDelegate = AuthFlowCoordinator(with: self)
        
        vpnDirect = true
        initVPNTunnelProviderManager(directConn: vpnDirect)
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
        // OIDC setup - from okta.plist (will occur in the delegate)
        accessToken = ""
        refreshToken = ""
        idToken = ""
        // Disable logoutButton until login occur
        logoutButton.isEnabled = false
        connectButton.isEnabled = false
    }
    
    override func viewWillDisappear() {
        super.viewWillDisappear();
        print("view will dissappear")
        
        if (vpnDirect) {
            connectDirectButton.title = "Disconnect"
            self.vpnManager.connection.stopVPNTunnel()
        } else {
            connectButton.title = "Disconnect"
            self.vpnManager.connection.stopVPNTunnel()
        }
    }
    
    override func viewWillAppear() {
        super.viewWillAppear()
        print("ViewController.viewWillAppear()")
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
        
        // self?.viewTokensButton.isEnabled = true
        logoutButton.isEnabled = true
        connectButton.isEnabled = true
        loginButton.isEnabled = false
        connectDirectButton.isEnabled = false
        
        // VPN configuration setup
        initVPNTunnelProviderManager(directConn: false)
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
        if (connectButton.title == "Disconnect") {
            self.vpnManager.loadFromPreferences { (error:Error?) in
                if let error = error {
                    print("VPN Manager load from preference error:", error.localizedDescription)
                }
                self.vpnManager.connection.stopVPNTunnel()
            }
            logoutButton.isEnabled = false
            connectButton.isEnabled = false
            loginButton.isEnabled = true
            connectDirectButton.isEnabled = true
        }
    }
    
    @IBAction func accessTokenViewTapped(_ sender: Any) {
    }
    
    @IBAction func refreshTokenViewTapped(_ sender: Any) {
    }

    private func initVPNTunnelProviderManager(directConn: Bool) {
        
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
                let tunnelBundleId = "io.nextensio.agent.tunnel"
                let serverAddress = "127.0.0.1"
                let serverPort = "8080"
                let mtu = "1500"
                let ip = "169.254.2.1"
                let subnet = "255.255.255.0"
                let dns = "8.8.8.8"

                let providerProtocol = NETunnelProviderProtocol()
                
                providerProtocol.providerBundleIdentifier = tunnelBundleId
                providerProtocol.providerConfiguration = ["port": serverPort,
                                                          "server": serverAddress,
                                                          "ip": ip,
                                                          "subnet": subnet,
                                                          "mtu": mtu,
                                                          "dns": dns,
                                                          "access": self.accessToken as Any,
                                                          "refresh": self.refreshToken as Any,
                                                          "id": self.idToken as Any,
                                                          "direct": directConn ? "true" : "false"
                ]
                providerProtocol.serverAddress = serverAddress
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
            print("vpn status connecting...")
            if (vpnDirect) {
                connectDirectButton.title = "Disconnect"
            } else {
                connectButton.title = "Disconnect"
            }
            break
        case .connected:
            print("vpn status connected...")
            if (vpnDirect) {
                connectDirectButton.title = "Disconnect"
            } else {
                connectButton.title = "Disconnect"
            }
            break
        case .disconnecting:
            print("vpn status disconnecting...")
            break
        case .disconnected:
            print("vpn status disconnected...")
            if (vpnDirect) {
                connectDirectButton.title = "Connect Direct"
            } else {
                connectButton.title = "Connect"
            }
            break
        case .invalid:
            print("vpn status invalid")
            break
        case .reasserting:
            print("vpn status reasserting...")
            break
        @unknown default:
            break
        }
    }

    @IBAction func connectDirect(_ sender: Any) {
        print("connectDirect pressed")
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
                        self.connectButton.isEnabled = false
                        self.loginButton.isEnabled = false
                        self.logoutButton.isEnabled = false
                    } catch {
                        print(error)
                    }
                } else {
                    print("stop vpn tunnel direct")
                    self.vpnManager.connection.stopVPNTunnel()
                    self.connectButton.isEnabled = false
                    self.loginButton.isEnabled = true
                    self.logoutButton.isEnabled = false
                }
            }
        })
    }
    
    @IBAction func connectTunnel(_ sender: Any) {
        print("connectTunnel pressed")
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
