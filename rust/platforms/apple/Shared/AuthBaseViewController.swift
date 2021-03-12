//
//  AuthBaseViewController.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 3/5/21.
//

import OktaOidc

class AuthBaseViewController: NSViewController {
    
    // State Manager
    var oidcStateManager: OktaOidcStateManager?
    
    // OIDC State Manager
    var accessToken: String?
    var refreshToken: String?
    var idToken: String?
    
    // Auth Flow Coordinator
    var authFlowCoordinatorDelegate: AuthFlowCoordinator?

    func loginUserProfile(title: String, subTitle: String, timeZone: String, locale: String, accessToken: Bool, refreshToken: Bool, stateManager: OktaOidcStateManager) {
        // empty, need to override by sub-class
    }
    
    func logoutUserProfile() {
        // empty, need to override by sub-class
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
