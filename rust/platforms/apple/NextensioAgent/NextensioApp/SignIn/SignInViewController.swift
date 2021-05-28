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

    var urlString = "https://dev-635657.okta.com"

    
    @IBOutlet private var usernameField: UITextField!
    @IBOutlet private var passwordField: UITextField!
    @IBOutlet private var signinButton: UIButton!

    let tunnelBundleId = "io.nextensio.agent1.tunnel"
    var vpnInited = false 
    var vpnManager: NETunnelProviderManager = NETunnelProviderManager()
    var oidcAuth: OktaOidc?
    var accessToken = ""
    var refreshToken = ""
    var idToken = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        
        usernameField.text = "username"
        passwordField.text = ""
    }
    
    @IBAction private func signInTapped() {
        guard let username = usernameField.text, !username.isEmpty,
              let password = passwordField.text, !password.isEmpty else { return }
        
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
            print("SignInViewController.errorBlock")
            _ = self?.showError(message: error.description)
        }

        let buttonTitle = signinButton.title(for: .normal) ?? ""
        if buttonTitle == "Sign In" {
            OktaAuthSdk.authenticate(with: URL(string: urlString)!,
                                    username: username,
                                    password: password,
                                    onStatusChange: successBlock,
                                    onError: errorBlock)
        } else {
            self.vpnManager.connection.stopVPNTunnel()
            signinButton.setTitle("Sign In", for: .normal)
            usernameField.isEnabled = true
            passwordField.isEnabled = true
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

                let providerProtocol = NETunnelProviderProtocol()
                providerProtocol.providerBundleIdentifier = self.tunnelBundleId
                providerProtocol.providerConfiguration = [
                                        "access": self.accessToken as Any,
                                        "refresh": self.refreshToken as Any,
                                        "id": self.idToken as Any,
                                        "highMem": false,
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
                        print("Save successfully")
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
            break
        case .connected:
            print("vpn status connected...")
            handleSignInButtons(status: true)
            break
        case .disconnecting:
            print("vpn status disconnecting...")
            break
        case .disconnected:
            print("vpn status disconnected...")
            handleSignInButtons(status: false)
            break
        case .invalid:
            print("vpn status invalid...")
            break
        case .reasserting:
            print("vpn status reasserting...")
            break
        @unknown default:
            break
        }
    }

    func handleSignInButtons(status: Bool) {
        if (status) {
            self.usernameField.isEnabled = false
            self.passwordField.isEnabled = false
            self.signinButton.setTitle("signout", for: .normal)
        } else {
            self.usernameField.isEnabled = true
            self.passwordField.isEnabled = true
            self.signinButton.setTitle("Sign In", for: .normal)
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
        var accessToken = false
        var refreshToken = false
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
}

