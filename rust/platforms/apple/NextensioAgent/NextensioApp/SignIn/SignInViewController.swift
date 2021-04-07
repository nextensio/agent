//
//  SignInViewController.swift
//  NextensioAgent
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import UIKit
import OktaAuthSdk

class SignInViewController: AuthBaseViewController {

    #warning ("Enter your Okta organization domain here")
    var urlString = "https://dev-635657.okta.com"

    class func instantiate() -> SignInViewController {
        print("instantiate SignInViewController")
        let signInStoryboard = UIStoryboard(name: "SignIn", bundle: nil)
        let signInViewController = signInStoryboard.instantiateViewController(withIdentifier: "SignInViewController") as! SignInViewController
        return signInViewController
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        usernameField.text = "rudy@nextensio.net"
        passwordField.text = "LetMeIn123"
        
        let backButton = UIBarButtonItem(title: "Back",
                                         style: .plain,
                                         target: self,
                                         action: #selector(backButtonTapped))
        self.navigationItem.setLeftBarButton(backButton, animated: true)
    }
    
    @objc override func backButtonTapped() {
        self.flowCoordinatorDelegate?.onCancel()
    }

    public func handleLockedOutStatus(status: OktaAuthStatusLockedOut) {
        let alert = UIAlertController(title: "Account Locked", message: "Your account is locked.\nWould you like to unlock account?", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Unlock", style: .default, handler: { _ in
            self.showAlertWithRecoverOptions(isPasswordRecoverFlow: false)
        }))
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    public func handleLockedOutSuccessStatus() {
        let alert = UIAlertController(title: "Success", message: "Your account has been successfully unlocked", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Ok", style: .cancel, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    private func startRecoverFlowWithFactor(_ factor: OktaRecoveryFactors, isPasswordRecoverFlow: Bool) {
        guard let username = usernameField.text, !username.isEmpty else {
            showError(message: "Please enter username")
            return
        }

        if isPasswordRecoverFlow {
            OktaAuthSdk.recoverPassword(with: URL(string: urlString)!,
                                        username: username,
                                        factorType: factor,
                                        onStatusChange:
                { [weak self] status in
                    self?.flowCoordinatorDelegate?.onStatusChanged(status: status)
            })  { [weak self] error in
                self?.showError(message: error.description)
            }
        } else {
            OktaAuthSdk.unlockAccount(with: URL(string: urlString)!,
                                      username: username,
                                      factorType: factor,
                                      onStatusChange:
                { [weak self] status in
                    self?.flowCoordinatorDelegate?.onStatusChanged(status: status)
            })  { [weak self] error in
                self?.showError(message: error.description)
            }
        }
    }

    // MARK: - IB
    
    @IBOutlet private var usernameField: UITextField!
    @IBOutlet private var passwordField: UITextField!
    @IBOutlet private var signInButton: UIButton!
    
    @IBAction private func signInTapped() {
        guard let username = usernameField.text, !username.isEmpty,
              let password = passwordField.text, !password.isEmpty else { return }
        
        let successBlock: (OktaAuthStatus) -> Void = { [weak self] status in
            self?.flowCoordinatorDelegate?.onStatusChanged(status: status)
        }

        let errorBlock: (OktaError) -> Void = { [weak self] error in
            self?.showError(message: error.description)
        }

        OktaAuthSdk.authenticate(with: URL(string: urlString)!,
                                username: username,
                                password: password,
                                onStatusChange: successBlock,
                                onError: errorBlock)
    }

    func showAlertWithRecoverOptions(isPasswordRecoverFlow: Bool) {
        let alert = UIAlertController(title: "Select recovery factor", message: nil, preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: "EMAIL", style: .default, handler: { _ in
            self.startRecoverFlowWithFactor(.email, isPasswordRecoverFlow: isPasswordRecoverFlow)
        }))
        alert.addAction(UIAlertAction(title: "SMS", style: .default, handler: { _ in
            self.startRecoverFlowWithFactor(.sms, isPasswordRecoverFlow: isPasswordRecoverFlow)
        }))
        alert.addAction(UIAlertAction(title: "CALL", style: .default, handler: { _ in
            self.startRecoverFlowWithFactor(.call, isPasswordRecoverFlow: isPasswordRecoverFlow)
        }))
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }

    @IBAction private func forgotPasswordTapped() {
        self.showAlertWithRecoverOptions(isPasswordRecoverFlow: true)
    }
}

