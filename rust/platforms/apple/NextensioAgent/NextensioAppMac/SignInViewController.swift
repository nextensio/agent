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
                print("sending message")
                try session.sendProviderMessage(message) { response in
                    if response != nil {
                        let value = response!.withUnsafeBytes {
                            $0.load(as: Int32.self)
                        }
                        self.progress = Int(value)
                        print("progress ", self.progress)
                    } else {
                        print("nil message")
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
            signinButton.title = "Authenticating.."
            progressView.doubleValue = 1/6
        } else if authenticated == 2 {
            signinButton.title = "Authenticated, initializing.."
            progressView.doubleValue = 2/6
        } else if authenticated == 3 {
            getConnectedStatus()
            if self.progress != 3 {
                signinButton.title = "Connecting.."
            } else {
                signinButton.title = "Connected, Sign Out"
            }
            progressView.doubleValue = (Double(self.progress) + 3)/6
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
        
        usernameField.stringValue = "username"
        passwordField.stringValue = ""
    }
    
    @IBAction func signInTapped(_ sender: Any) {
        guard let username = usernameField?.stringValue, !username.isEmpty,
              let password = passwordField?.stringValue, !password.isEmpty else { return }
        
        if !self.sysext {
            return
        }

        let successBlock: (OktaAuthStatus) -> Void = { [weak self] status in
            switch status.statusType {
            case .success:
                let state: OktaAuthStatusSuccess = status as! OktaAuthStatusSuccess
                print("SignInViewController.successBlock")
                self?.oidcAuthenticateUser(status: state)
                break
            default:
                print("Authentication failed")
                _ = self?.showError(message: "Authentication failed")
                break
            }
        }

        let errorBlock: (OktaError) -> Void = { [weak self] error in
            _ = self?.showError(message: error.description)
        }

        if authenticated == 0 {
            // Authenticate SesssionToken
            authenticated = 1
            OktaAuthSdk.authenticate(with: URL(string: urlString)!,
                                     username: username,
                                     password: password,
                                     onStatusChange: successBlock,
                                     onError: errorBlock)
        } else {
            self.vpnManager.connection.stopVPNTunnel()
            signinButton.title = "Sign In"
            usernameField.isEnabled = true
            passwordField.isEnabled = true
            authenticated = 0
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
            authenticated = 2
            break
        case .connected:
            print("vpn status connected...")
            authenticated = 3
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

    func createOidcClient() -> OktaOidc? {
        if oidcAuth != nil {
            return oidcAuth
        }
        oidcAuth = try! OktaOidc()
        return oidcAuth
    }

    func oidcAuthenticateUser(status: OktaAuthStatusSuccess) {
        print("AuthFlowCoordinator.oidcAuthenticateUser")
        let successStatus = status
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            guard let oidcClient = self.createOidcClient() else {
                return
            }
            oidcClient.authenticate(withSessionToken: successStatus.sessionToken!, callback: { [weak self] stateManager, error in
                if let error = error {
                    print("AuthFlowCoordinator.authenticate error", error.localizedDescription)
                    return
                }
                print("AuthFlowCoordinator user authenticated")
                self?.loginUserProfile(stateManager: stateManager!)
            })
        }
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

