//
//  AuthFlowCoordinator.swift
//  NextensioAgent
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import Foundation
import UIKit
import OktaAuthSdk

class AuthFlowCoordinator {
    
    public let rootViewController: UINavigationController
    public var currentStatus: OktaAuthStatus?
    
    public class func instantiate() -> AuthFlowCoordinator {
        print("instantiate AuthFlowCoordinator")

        let tunnelViewController = AuthBaseViewController.instantiate(with: nil,
                                                                      flowCoordinatorDelegate: nil,
                                                                      storyBoardName: "Tunnel",
                                                                      viewControllerIdentifier: "Tunnel") as! AuthBaseViewController
        let navigationViewController = UINavigationController(rootViewController: tunnelViewController)
        let flowCoordinator = AuthFlowCoordinator(with: navigationViewController)
        tunnelViewController.flowCoordinatorDelegate = flowCoordinator
        return flowCoordinator
    }
    
    public init(with rootViewController: UINavigationController) {
        self.rootViewController = rootViewController
        print("init rootViewController")
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
                self.handleFactorRequired(status: status)
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
                let authBaseViewController = rootViewController.topViewController as! AuthBaseViewController
                authBaseViewController.showError(message: "Unexpected status")
            case .unknown(_):
                let authBaseViewController = rootViewController.topViewController as! AuthBaseViewController
                authBaseViewController.showError(message: "Recieved unknown status")
        }
    }
    
    func startAuthenticationFlow(status: OktaAuthStatus?) {
        print("startAuthenticationFlow")
        
        let signInViewController = AuthBaseViewController.instantiate(with: status,
                                                                      flowCoordinatorDelegate: self,
                                                                      storyBoardName: "SignIn",
                                                                      viewControllerIdentifier: "SignIn")
        
        print("startAuthenticationFlow pushViewController")

        // Make SignInViewController as ROOT view
        rootViewController.pushViewController(signInViewController, animated: true)
    }
    
    func handleTerminateAuthView() {
        let authBaseViewController = rootViewController.topViewController as! AuthBaseViewController
        authBaseViewController.terminateAuthView()
    }

    func handleSuccessStatus(status: OktaAuthStatus) {
        let successStatus = status as! OktaAuthStatusSuccess
        if let _ = successStatus.sessionToken {
            let userProfileViewController = AuthBaseViewController.instantiate(with: status,
                                                                            flowCoordinatorDelegate: self,
                                                                            storyBoardName: "UserProfile",
                                                                            viewControllerIdentifier: "UserProfile")
            rootViewController.pushViewController(userProfileViewController, animated: true)
        } else {
            handleLockedOutSuccess(status: successStatus)
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
        let factorActivate: OktaAuthStatusFactorEnrollActivate = status as! OktaAuthStatusFactorEnrollActivate
        handleActivateForFactor(factor: factorActivate.factor, status: status)
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
        rootViewController.popToRootViewController(animated: true)
        let signInViewController = rootViewController.topViewController as! SignInViewController
        signInViewController.handleLockedOutStatus(status: status as! OktaAuthStatusLockedOut)
    }

    func handleLockedOutSuccess(status: OktaAuthStatus) {
        rootViewController.popToRootViewController(animated: true)
        let signInViewController = rootViewController.topViewController as! SignInViewController
        signInViewController.handleLockedOutSuccessStatus()
    }
}

extension AuthFlowCoordinator: AuthFlowCoordinatorProtocol {
    
    func onInitAuthentication(status: OktaAuthStatus?) {
        print("onInitAuthentication")
        self.startAuthenticationFlow(status: status)
    }
    
    func onStatusChanged(status: OktaAuthStatus) {
        print("onStatusChanged")
        self.handleStatus(status: status)
    }
    
    func onCancel() {
        print("onCancel")
        rootViewController.popToRootViewController(animated: true)
    }

    func onReturn(prevStatus: OktaAuthStatus) {
        print("onReturn")
        let authViewController = rootViewController.viewControllers.first { viewController in
            let authViewController = viewController as! AuthBaseViewController
            if authViewController.status?.statusType == prevStatus.statusType {
                return true
            }
            return false
        }
        
        if let authViewController = authViewController as? AuthBaseViewController {
            authViewController.status = prevStatus
            rootViewController.popViewController(animated: true)
        }
    }
    
    func onLoggedOut() {
        print("onLoggedOut")
        rootViewController.popToRootViewController(animated: true)
    }
}
