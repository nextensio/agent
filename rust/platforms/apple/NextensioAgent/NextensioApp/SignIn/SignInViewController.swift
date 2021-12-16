//
//  SignInViewController.swift
//  NextensioAgent
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import UIKit
import OktaAuthSdk
import OktaOidc
import NetworkExtension

class SignInViewController: AuthBaseViewController {

    var urlString = "https://login.nextensio.net"

    
    @IBOutlet private var usernameField: UITextField!
    @IBOutlet private var passwordField: UITextField!
    @IBOutlet private var signinButton: UIButton!
    @IBOutlet weak var progressView: UIProgressView!
    
    let tunnelBundleId = "io.nextensio.agent1.tunnel"
    var vpnInited = false 
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    var oidcAuth: OktaOidc?
    var accessToken = ""
    var refreshToken = ""
    var idToken = ""
    var progressBarTimer: Timer!
    var authenticated = 0
    var progress = 0
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        progressView.progress = 0
        progressView.progressTintColor = UIColor.blue
        progressView.progressViewStyle = .bar
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
            signinButton.setTitle("Sign In", for: .normal)
            progressView.progress = 0
        } else if authenticated == 1 {
            signinButton.setTitle("Authenticating..", for: .normal)
            progressView.progress = 1/6
        } else if authenticated == 2 {
            signinButton.setTitle("Authenticated, initializing..", for: .normal)
            progressView.progress = 2/6
        } else if authenticated == 3 {
            getConnectedStatus()
            if self.progress != 3 {
                signinButton.setTitle("Connecting..", for: .normal)
            } else {
                signinButton.setTitle("Connected, Sign Out", for: .normal)
            }
            progressView.progress = (Float(self.progress) + 3)/6
        }
        progressView.setProgress(progressView.progress, animated: true)
    }
    
    @IBAction private func signInTapped() {
        guard let username = usernameField.text, !username.isEmpty,
              let password = passwordField.text, !password.isEmpty else { return }
        
        let successBlock: (OktaAuthStatus) -> Void = { [weak self] status in
            switch status.statusType {
            case .success:
                let state: OktaAuthStatusSuccess = status as! OktaAuthStatusSuccess
                self?.oidcAuthenticateUser(status: state)
                break
            default:
                _ = self?.showError(message: "Authentication failed")
                break
            }
        }

        let errorBlock: (OktaError) -> Void = { [weak self] error in
            print("SignInViewController.errorBlock")
            _ = self?.showError(message: error.description)
            self?.authenticated = 0
        }

        if authenticated != 0 {
            self.vpnManager.connection.stopVPNTunnel()
            authenticated = 0
        }
        authenticated = 1
        OktaAuthSdk.authenticate(with: URL(string: urlString)!,
                                username: username,
                                password: password,
                                onStatusChange: successBlock,
                                onError: errorBlock)
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
            if let _ = error {
                self.showError(message: "Cannot load configs, please try again")
            }
            if let savedManagers = savedManagers {
                if savedManagers.count > 0 {
                    self.vpnManager = savedManagers[0]
                }
            }

            self.vpnManager.loadFromPreferences(completionHandler: { (error:Error?) in
                if let _ = error {
                    self.showError(message: "Cannot load configs, please try again")
                }

                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = [
                                        "access": self.accessToken as Any,
                                        "refresh": self.refreshToken as Any,
                                        "id": self.idToken as Any,
                                        "highMem": false,
                                        "modelName": UIDevice.current.modelName,
                ]
                providerProtocol.serverAddress = "127.0.0.1"
                
                self.vpnManager.protocolConfiguration = providerProtocol
                self.vpnManager.localizedDescription = "nextensio"
                self.vpnManager.isEnabled = true
                self.vpnManager.saveToPreferences(completionHandler: { (error:Error?) in
                    if let _ = error {
                        self.showError(message: "Cannot save configs, please try again")
                    } else {
                        if connect {
                            do {
                                try self.vpnManager.connection.startVPNTunnel()
                            } catch {
                                self.showError(message: "Cannot start Nextensio, please try again")
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
        let successStatus = status
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            guard let oidcClient = self.createOidcClient() else {
                return
            }
            oidcClient.authenticate(withSessionToken: successStatus.sessionToken!, callback: { [weak self] stateManager, error in
                if let _ = error {
                    return
                }
                self?.loginUserProfile(stateManager: stateManager!)
            })
        }
    }
}

extension UIDevice {
    var modelName: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }
}
