//
//  AuthFlowCoordinatorProtocol.swift
//  Nextensio
//
//  Created by Rudy Zulkarnain on 3/5/21.
//

import Foundation
import OktaAuthSdk

protocol AuthFlowCoordinatorProtocol: class {
    func onStatusChanged(status: OktaAuthStatus)
    func onCancel()
    func onReturn(prevStatus: OktaAuthStatus)
    func onLoggedOut()
}
