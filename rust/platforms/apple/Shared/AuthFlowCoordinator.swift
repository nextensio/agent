//
//  AuthFlowCoordinator.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 3/5/21.
//

import Foundation
import OktaOidc
import OktaAuthSdk

class AuthFlowCoordinator: AuthFlowCoordinatorProtocol {
    
    var oidcAuth: OktaOidc?
    var currentStatus: OktaAuthStatus?
    var vc: AuthBaseViewController?

    func onStatusChanged(status: OktaAuthStatus) {
        print("AuthFlowCoordinator.onStatusChanged")
        self.handleStatus(status: status)
    }
    
    func onCancel() {
    }

    func onReturn(prevStatus: OktaAuthStatus) {
    }
    
    func onLoggedOut() {
        if let oidcStateManager = self.vc?.oidcStateManager {
            print("AuthFlowCoordinator.onLoggedOut oidcStateManager set")
            
            let access = self.vc?.accessToken
            // let refresh = self.vc?.refreshToken
            
            oidcStateManager.revoke(access) { response, error in
                if let error = error {
                    print("AuthFlowCoordinator error in revoke", error.localizedDescription)
                    return
                }
                print("AuthFlowCoordinator revoke access token successful")
            }
            
            // oidcStateManager.clear()
            // print("AuthFlowCoordinator clearing oidc state successful")
            
            self.vc?.logoutUserProfile()
            print("AuthFlowCoordinator logout User Profile")
        }
    }
    
    public init(with vc: AuthBaseViewController) {
        self.vc = vc
    }

    func handleStatus(status: OktaAuthStatus) {
        currentStatus = status
        
        switch status.statusType {
        case .success:
            handleSuccessStatus(status: status)
        case .passwordWarning:
            handlePasswordWarning(status: status)
        case .passwordExpired:
            handlePasswordExpired(status: status)
        case .MFARequired:
            handleFactorRequired(status: status)
        case .MFAChallenge:
            handleFactorChallenge(status: status)
        case .MFAEnroll:
            handleFactorEnrollment(status: status)
        case .MFAEnrollActivate:
            handleFactorEnrollActivate(status: status)
        case .recoveryChallenge:
            handlePasswordRecoveryChallenge(status: status)
        case .recovery:
            handlePasswordRecovery(status: status)
        case .passwordReset:
            handlePasswordReset(status: status)
        case .lockedOut:
            handleLockedOut(status: status)
        case .unauthenticated:
            _ = ""
        case .unknown(_):
            _ = ""
        }
    }

    func handleSuccessStatus(status: OktaAuthStatus) {
        let successStatus = status as! OktaAuthStatusSuccess
        if let _ = successStatus.sessionToken {
            print("AuthFlowCoordinator.handleSuccessStatus.sessionToken is set")
            oidcAuthenticateUser(status: successStatus)
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
        let title = "Welcome, \(successStatus.model.embedded?.user?.profile?.firstName ?? "-")"
        guard let subTitle = successStatus.model.embedded?.user?.profile?.login else { return }
        guard let timeZone = successStatus.model.embedded?.user?.profile?.timeZone else { return }
        guard let locale = successStatus.model.embedded?.user?.profile?.locale else { return }
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
                if let _ = stateManager?.accessToken {
                    accessToken = true
                }
                if let _ = stateManager?.refreshToken {
                    refreshToken = true
                }
                
                print("AuthFlowCoordinator user authenticated")

                self?.vc?.loginUserProfile(title: title, subTitle: subTitle, timeZone: timeZone, locale: locale, accessToken: accessToken, refreshToken: refreshToken, stateManager: stateManager!)
            })
        }
    }
    

    func handlePasswordWarning(status: OktaAuthStatus) {
    }

    func handlePasswordExpired(status: OktaAuthStatus) {
    }

    func handleFactorRequired(status: OktaAuthStatus) {
    }

    func handleFactorChallenge(status: OktaAuthStatus) {
    }

    func handleChallengeForFactor(factor: OktaFactor, status: OktaAuthStatus) {
    }

    func handleFactorEnrollment(status: OktaAuthStatus) {
    }

    func handleFactorEnrollActivate(status: OktaAuthStatus) {
    }

    func handleActivateForFactor(factor: OktaFactor, status: OktaAuthStatus) {
    }

    func handlePasswordRecoveryChallenge(status: OktaAuthStatus) {
    }

    func handlePasswordRecovery(status: OktaAuthStatus) {
    }

    func handlePasswordReset(status: OktaAuthStatus) {
    }

    func handleLockedOut(status: OktaAuthStatus) {
    }

    func handleLockedOutSuccess(status: OktaAuthStatus) {
    }
}
