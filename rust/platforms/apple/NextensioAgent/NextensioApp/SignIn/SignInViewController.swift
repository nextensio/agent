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

    @IBOutlet private var signinButton: UIButton!
    @IBOutlet weak var progressView: UIProgressView!
    
    let tunnelBundleId = "io.nextensio.agent1.tunnel"
    var vpnInited = false 
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    var oidcAuth: OktaOidc?
    var stateManager: OktaOidcStateManager?
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
        createOidcClient()
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
            signinButton.setTitle("Authenticated, initializing..", for: .normal)
            progressView.progress = 1/5
        } else if authenticated == 2 {
            getConnectedStatus()
            if self.progress != 3 {
                signinButton.setTitle("Connecting..", for: .normal)
            } else {
                signinButton.setTitle("Connected, Sign Out", for: .normal)
            }
            progressView.progress = (Float(self.progress) + 2)/5
        }
        progressView.setProgress(progressView.progress, animated: true)
    }
    
    @IBAction private func signInTapped() {
        if authenticated != 0 {
            guard let oktaOidc = self.oidcAuth,
                  let stateManager = self.stateManager else { return }
            
            oktaOidc.signOutOfOkta(stateManager, from: self, callback: { [weak self] error in
                if let error = error {
                    let alert = UIAlertController(title: "Error", message: error.localizedDescription, preferredStyle: .alert)
                    alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                    self?.present(alert, animated: true, completion: nil)
                    return
                }
                
                self?.stateManager?.clear()
            })
            self.vpnManager.connection.stopVPNTunnel()
            authenticated = 0
        } else {
            oidcAuth?.signInWithBrowser(from: self, callback: { [weak self] stateManager, error in
                if let error = error {
                    let alert = UIAlertController(title: "Error", message: error.localizedDescription, preferredStyle: .alert)
                    alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                    self?.present(alert, animated: true, completion: nil)
                    return
                }
                self?.stateManager?.clear()
                self?.stateManager = stateManager
                self?.loginUserProfile()
            })
        }
    }

    func loginUserProfile() {
        self.accessToken = ""
        self.refreshToken = ""
        self.idToken = ""
        if let access = self.stateManager?.accessToken {
            self.accessToken = access
        } 
        if let refresh = self.stateManager?.refreshToken {
            self.refreshToken = refresh
        } 
        if let id = self.stateManager?.idToken {
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

    func createOidcClient() -> OktaOidc? {
        if oidcAuth != nil {
            return oidcAuth
        }
        oidcAuth = try! OktaOidc()
        return oidcAuth
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
