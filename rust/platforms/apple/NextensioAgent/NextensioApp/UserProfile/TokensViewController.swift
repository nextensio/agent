//
//  TokensViewController.swift
//  NextensioApp
//
//  Created by Rudy Zulkarnain on 4/5/21.
//

import UIKit
import OktaOidc

class TokensViewController: UIViewController {

    @IBOutlet private var tokensView: UITextView!
    @IBOutlet private var refreshButton: UIButton!
    
    @IBOutlet private var activityIndicator: UIActivityIndicatorView!
    
    var stateManager: OktaOidcStateManager? {
        didSet {
            configure()
        }
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        configure()
    }
    
    @IBAction func refreshTapped() {
        stateManager?.renew(callback: { stateManager, error in
            if let error = error {
                self.showError(error.localizedDescription)
                return
            }

            self.configure()
            self.showAlert(title: "Token refreshed!")
        })
    }
}

// UI Utils
private extension TokensViewController {
    func configure() {
        guard isViewLoaded else { return }
        
        var tokens = ""
        if let accessToken = stateManager?.accessToken,
           let decodedToken = try? OktaOidcStateManager.decodeJWT(accessToken) {
            tokens += "Access token:\n\(decodedToken)\n\n"
            print("Access token:\n\(decodedToken)")
        }
        
        if let refreshToken = stateManager?.refreshToken {
            tokens += "Refresh token:\n\(refreshToken)\n\n"
        }
        
        if let idToken = stateManager?.idToken,
           let decodedToken = try? OktaOidcStateManager.decodeJWT(idToken) {
            tokens += "ID token:\n\(decodedToken)"
            print("ID token:\n\(decodedToken)")
        }
        
        tokensView.text = tokens
    }
    
    func showAlert(title: String, message: String? = nil) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .cancel, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }
    
    func showError(_ message: String) {
        self.showAlert(title: "Error", message: message)
    }
    
    func startProgress() {
        self.activityIndicator.startAnimating()
        self.refreshButton.isEnabled = false
    }
    
    func stopProgress() {
        self.activityIndicator.stopAnimating()
        self.refreshButton.isEnabled = true
    }
}
