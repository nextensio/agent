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
   
    // VPN Constructs
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    // Hard code VPN configurations
    let tunnelBundleId = "com.nextensio.io.vpn.NextensioApp.NextensioPacketTunnel"
    let serverAddress = "127.0.0.1"
    let serverPort = "8080"
    let mtu = "1500"
    let ip = "169.254.2.1"
    let subnet = "255.255.255.0"
    let dns = "8.8.8.8"

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        
        print("ViewController.init")

        authFlowCoordinatorDelegate = AuthFlowCoordinator(with: self)
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

        print("viewController.viewDidLoad()")
        
        // OIDC setup - from okta.plist (will occur in the delegate)
        accessToken = ""
        refreshToken = ""
        idToken = ""
        
        // Disable logoutButton until login occur
        logoutButton.isEnabled = false
        connectButton.isEnabled = false
        
        // VPN configuration setup
//        initVPNTunnelProviderManager()
//        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
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
        
//        var tokens = ""
//        if let accessToken = oidcStateManager?.accessToken,
//           let decodedToken = try? OktaOidcStateManager.decodeJWT(accessToken) {
//            accessTokenBase64 = oidcStateManager?.accessToken
//            tokens += "Access token:\n\(decodedToken)\n\n"
//        }
//        print("Token:\n\(tokens)")
        
        // self?.viewTokensButton.isEnabled = true
        logoutButton.isEnabled = true
        connectButton.isEnabled = true
        
        // VPN configuration setup
        initVPNTunnelProviderManager()
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
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
        // remove from secureStorage
        
        // Toggle VPN Button from Connect -> Disconnect
        if (connectButton.title == "Disconnect") {
            self.vpnManager.loadFromPreferences { (error:Error?) in
                if let error = error {
                    print("VPN Manager load from preference error:", error.localizedDescription)
                }
                self.vpnManager.connection.stopVPNTunnel()
            }
            connectButton.isEnabled = false
        }
    }
    
    @IBAction func accessTokenViewTapped(_ sender: Any) {
    }
    
    @IBAction func refreshTokenViewTapped(_ sender: Any) {
    }

    private func initVPNTunnelProviderManager() {
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

                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = ["port": self.serverPort,
                                                          "server": self.serverAddress,
                                                          "ip": self.ip,
                                                          "subnet": self.subnet,
                                                          "mtu": self.mtu,
                                                          "dns": self.dns,
                                                          "access": self.accessToken as Any,
                                                          "refresh": self.refreshToken as Any,
                                                          "id": self.idToken as Any
                ]
                providerProtocol.serverAddress = self.serverAddress
                self.vpnManager.protocolConfiguration = providerProtocol
                self.vpnManager.localizedDescription = "nextensio.io"
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
    }
    
    @objc func VPNStatusDidChange(_ notification: Notification?) {
        print("VPN Status changed:")
        let status = self.vpnManager.connection.status
        switch status {
        case .connecting:
            print("VPNStatusDisChange Connecting...")
            connectButton.title = "Disconnect"
            break
        case .connected:
            print("VPNStatusDisChange Connected...")
            connectButton.title = "Disconnect"
            break
        case .disconnecting:
            print("VPNStatusDisChange Disconnecting...")
            break
        case .disconnected:
            print("VPNStatusDisChange Disconnected...")
            connectButton.title = "Connect"
            break
        case .invalid:
            print("VPNStatusDisChange Invalid")
            break
        case .reasserting:
            print("VPNStatusDisChange Reasserting...")
            break
        @unknown default:
            break
        }
    }

    @IBAction func connect_button(_ sender: Any) {
        print("Go!")
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
