//
//  SignInViewController.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 3/5/21.
//

import Cocoa
import OktaAuthSdk
import OktaOidc
import NetworkExtension
import SystemExtensions
import os.log

class SignInViewController: NSViewController, OSSystemExtensionRequestDelegate {
    var urlString = "https://login.nextensio.net"
    
    @IBOutlet weak var usernameField: NSTextField!
    @IBOutlet weak var passwordField: NSSecureTextField!
    @IBOutlet weak var signinButton: NSButton!
    @IBOutlet weak var progressView: NSProgressIndicator!
    
    let tunnelBundleId = "io.nextensio.agent1.tunnel"
    var vpnInited = false
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    var oidcAuth: OktaOidc?
    var stateManager: OktaOidcStateManager?
    var sysext = false
    var accessToken = ""
    var refreshToken = ""
    var idToken = ""
    var progressBarTimer: Timer!
    var authenticated = 0
    var progress = 0
    
    // Get the Bundle of the system extension.
    lazy var extensionBundle: Bundle = {

        let extensionsDirectoryURL = URL(fileURLWithPath: "Contents/Library/SystemExtensions", relativeTo: Bundle.main.bundleURL)
        let extensionURLs: [URL]
        do {
            extensionURLs = try FileManager.default.contentsOfDirectory(at: extensionsDirectoryURL,
                                                                        includingPropertiesForKeys: nil,
                                                                        options: .skipsHiddenFiles)
        } catch let error {
            fatalError("Failed to get the contents of \(extensionsDirectoryURL.absoluteString): \(error.localizedDescription)")
        }

        guard let extensionURL = extensionURLs.first else {
            fatalError("Failed to find any system extensions")
        }

        guard let extensionBundle = Bundle(url: extensionURL) else {
            fatalError("Failed to create a bundle with URL \(extensionURL.absoluteString)")
        }

        return extensionBundle
    }()

    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
	os_log("system extension replace")
	return .replace
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
	os_log("system extension user approval")
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if #available(macOS 11.0, *) {
            os_log("system extension failed %{public}s", error.localizedDescription)
        } else {
            // Fallback on earlier versions
        }
    }
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
	os_log("system extension success")
	self.sysext = true
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
    }


    override func viewWillAppear() {
        super.viewWillAppear()
        os_log("SignInViewController.viewWillAppear")
        guard let extensionIdentifier = extensionBundle.bundleIdentifier else {
       	    os_log("SignInViewController.viewWillAppear, no bundle identifier")
            _ = self.showError(message: "Cannot load required software, please try again")
            return
        }

        // Start by activating the system extension
        let activationRequest = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        activationRequest.delegate = self
        OSSystemExtensionManager.shared.submitRequest(activationRequest)
        os_log("system extension activation sent")
        
        progressView.doubleValue = 0
        progressView.minValue = 0
        progressView.maxValue = 1
        self.progressBarTimer = Timer.scheduledTimer(timeInterval: 1.0, target: self, selector: #selector(SignInViewController.updateProgressView), userInfo: nil, repeats: true)
    }
    
    func getConnectedStatus() {
        if let session = self.vpnManager.connection as? NETunnelProviderSession,
           let message = "progress".data(using: String.Encoding.utf8)
            , self.vpnManager.connection.status != .invalid
        {
            do {
                try session.sendProviderMessage(message) { response in
                    if response != nil {
                        let value = response!.withUnsafeBytes {
                            $0.load(as: Int32.self)
                        }
                        self.progress = Int(value)
                    } 
                }
            } catch {
            }
        }
    }
    
    @objc func updateProgressView() {
        if authenticated == 0 {
            signinButton.title = "Sign In"
            progressView.doubleValue = 0
        } else if authenticated == 1 {
            signinButton.title = "Authenticated, initializing.."
            progressView.doubleValue = 1/5
        } else if authenticated == 2 {
            getConnectedStatus()
            if self.progress != 3 {
                signinButton.title = "Connecting.."
            } else {
                signinButton.title = "Connected, Sign Out"
            }
            progressView.doubleValue = (Double(self.progress) + 2)/5
        } else if authenticated == 3 {
            signinButton.title = "Error, Sign In Again"
            progressView.doubleValue = 0
        }
    }
    
    @objc func Uninstall() {
        guard let extensionIdentifier = extensionBundle.bundleIdentifier else {
            os_log("SignInViewController.viewWillAppear, no bundle identifier")
            return
        }
        let activationRequest = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        activationRequest.delegate = self
        OSSystemExtensionManager.shared.submitRequest(activationRequest)
    }

    override func viewWillDisappear() {
        super.viewWillDisappear();
        print("view will dissappear")
        self.vpnManager.connection.stopVPNTunnel()
        vpnInited = false
    }
    

    override func viewDidLoad() {
        super.viewDidLoad()
        print("SignInViewController.viewDidLoad")
        createOidcClient()
    }
    
    @IBAction private func signInTapped(_ sender: Any) {
        if !self.sysext {
            return
        }
        if authenticated != 0 {
            guard let oktaOidc = self.oidcAuth,
                  let stateManager = self.stateManager else { return }
            let serverConfig = OktaRedirectServerConfiguration.default
            serverConfig.domainName = "localhost"
            serverConfig.port = 8180
            oktaOidc.signOutOfOkta(authStateManager: stateManager, redirectServerConfiguration: serverConfig, callback: { [weak self] error in
                if let error = error {
                    os_log("Error signing out %{PUBLIC}@", String(describing: error))
                    return
                }
                
                self?.stateManager?.clear()
            })
            self.vpnManager.connection.stopVPNTunnel()
            authenticated = 0
        } else {
            let serverConfig = OktaRedirectServerConfiguration.default
            serverConfig.domainName = "localhost"
            serverConfig.port = 8180
            self.oidcAuth?.signInWithBrowser(redirectServerConfiguration: serverConfig, callback: { [weak self] stateManager, error in
                if let error = error {
                    os_log("Error signing in %{PUBLIC}@", String(describing: error))
                    self?.authenticated = 3
                    return
                }
                self?.stateManager?.clear()
                self?.stateManager = stateManager
                self?.loginUserProfile(stateManager: stateManager!)
            })
        }
    }

    func loginUserProfile(stateManager: OktaOidcStateManager) {
        self.accessToken = ""
        self.refreshToken = ""
        self.idToken = ""
        if let access = stateManager.accessToken {
            self.accessToken = access
        } 
        if let refresh = stateManager.refreshToken {
            self.refreshToken = refresh
        } 
        if let id = stateManager.idToken {
            self.idToken = id
        }
        // VPN configuration setup
        initVPNTunnelProviderManager(connect: true)
    }

    private func initVPNTunnelProviderManager(connect: Bool) {
        NETunnelProviderManager.loadAllFromPreferences { (savedManagers: [NETunnelProviderManager]?, error: Error?) in
            if let error = error {
		print(error)
                _ = self.showError(message: "Cannot load configs, please try again")
            }
            if let savedManagers = savedManagers {
                if savedManagers.count > 0 {
                    self.vpnManager = savedManagers[0]
                }
            }
            
            self.vpnManager.loadFromPreferences(completionHandler: { (error:Error?) in
                if let error = error {
                    print(error)
                    _ = self.showError(message: "Cannot load configs, please try again")
                }
                
                // Hard code VPN configurations
                let providerProtocol = NETunnelProviderProtocol()
                
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = [
                                                          "access": self.accessToken as Any,
                                                          "refresh": self.refreshToken as Any,
                                                          "id": self.idToken as Any,
                                                          "highMem": true,
                ]
                providerProtocol.serverAddress = "127.0.0.1"
                self.vpnManager.protocolConfiguration = providerProtocol
                self.vpnManager.localizedDescription = "nextensio"
                self.vpnManager.isEnabled = true

                self.vpnManager.saveToPreferences(completionHandler: { (error:Error?) in
                    if let error = error {
                        print(error)
                        _ = self.showError(message: "Cannot save configs, please try again")
                    } else {
                        print("Saved successfully")
                        if connect {
                            do {
                                try self.vpnManager.connection.startVPNTunnel()
                            } catch {
                                print(error)
                                _ = self.showError(message: "Cannot start Nextensio, please try again")
                            }
                        }
                    }
                })
                self.VPNStatusDidChange(nil)
            })
        }
        
        if (vpnInited == false) {
            NotificationCenter.default.addObserver(self, selector: #selector(SignInViewController.VPNStatusDidChange(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
            vpnInited = true
        }
    }
    
    @objc func VPNStatusDidChange(_ notification: Notification?) {
        let status = self.vpnManager.connection.status
        switch status {
        case .connecting:
            print("vpn status connecting...")
            authenticated = 1
            break
        case .connected:
            print("vpn status connected...")
            authenticated = 2
            break
        case .disconnecting:
            print("vpn status disconnecting...")
            authenticated = 0
            break
        case .disconnected:
            print("vpn status disconnected...")
            authenticated = 0
            break
        case .invalid:
            print("vpn status invalid...")
            authenticated = 0
            break
        case .reasserting:
            print("vpn status reasserting...")
            authenticated = 0
            break
        @unknown default:
            authenticated = 0
            break
        }
    }

    func createOidcClient()  {
        if oidcAuth != nil {
            return
        }
        oidcAuth = try! OktaOidc()
        return
    }
    
    func showError(message: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Error"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

