//
//  SignInViewController.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 3/5/21.
//

import Cocoa
import OktaAuthSdk

class SignInViewController: AuthBaseViewController {
    
    var urlString = "https://dev-635657.okta.com"
    
    @IBOutlet weak var usernameField: NSTextField!
    @IBOutlet weak var passwordField: NSSecureTextField!
    @IBOutlet weak var signInButton: NSButton!
    @IBOutlet weak var cancelButton: NSButton!
    
    override func viewWillAppear() {
        super.viewWillAppear()
        print("SignInViewController.viewWillAppear")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        print("SignInViewController.viewDidLoad")
        
        usernameField.stringValue = "rudy@nextensio.net"
        passwordField.stringValue = "LetMeIn123"
    }
    
    @IBAction func cancelTapped(_ sender: Any) {
        self.dismiss(self)
//        if let controller = self.storyboard?.instantiateController(withIdentifier: "ViewController") as? ViewController {
//            self.view.window?.contentViewController = controller
//        }
    }
    
    @IBAction func signInTapped(_ sender: Any) {
        guard let username = usernameField?.stringValue, !username.isEmpty,
              let password = passwordField?.stringValue, !password.isEmpty else { return }
        
        let successBlock: (OktaAuthStatus) -> Void = { [weak self] status in
            print("SignInViewController.successBlock")
            self?.authFlowCoordinatorDelegate?.onStatusChanged(status: status)
            self?.dismiss(self)
        }

        let errorBlock: (OktaError) -> Void = { [weak self] error in
            print("SignInViewController.errorBlock")
            _ = self?.showError(message: error.description)
        }

        // Authenticate SesssionToken
        OktaAuthSdk.authenticate(with: URL(string: urlString)!,
                                     username: username,
                                     password: password,
                                     onStatusChange: successBlock,
                                     onError: errorBlock)
    }
}

