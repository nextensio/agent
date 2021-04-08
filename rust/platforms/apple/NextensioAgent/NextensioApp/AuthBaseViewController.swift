/*
 * Copyright 2019 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import UIKit
import OktaAuthSdk

class AuthBaseViewController: UIViewController {
    
    var status: OktaAuthStatus?
    weak var flowCoordinatorDelegate: AuthFlowCoordinatorProtocol?

    public class func instantiate(with status: OktaAuthStatus?,
                            flowCoordinatorDelegate: AuthFlowCoordinatorProtocol?,
                            storyBoardName: String,
                            viewControllerIdentifier: String) -> UIViewController {
        
        print("instantiate AuthBaseViewController storyBoard =", storyBoardName)

        let mainStoryboard = UIStoryboard(name: storyBoardName, bundle: nil)
        let viewController = mainStoryboard.instantiateViewController(withIdentifier: viewControllerIdentifier) as! AuthBaseViewController
        viewController.status = status
        viewController.flowCoordinatorDelegate = flowCoordinatorDelegate
        
        return viewController
    }

    override func viewDidLoad() {
        print("AuthBaseView viewDidLoad()")
        if let status = status, status.canReturn() {
            let backButton = UIBarButtonItem(title: "Back",
                                             style: .plain,
                                             target: self,
                                             action: #selector(backButtonTapped))
            self.navigationItem.setLeftBarButton(backButton, animated: true)
        } else {
            self.navigationItem.setHidesBackButton(true, animated: false)
        }
    }

    func showError(message: String) {
        let alert = UIAlertController(title: "Error", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        present(alert, animated: true, completion: nil)
    }

    func processCancel() {
        status?.cancel()
        self.flowCoordinatorDelegate?.onCancel()
    }

    @objc func backButtonTapped() {
        status?.returnToPreviousStatus(onStatusChange: { [weak self] status in
            self?.flowCoordinatorDelegate?.onReturn(prevStatus: status)
        }, onError: { [weak self] error in
            self?.showError(message: error.description)
        })
    }
}

internal extension UIView{
    func flash() {
        self.alpha = 0.1
        UIView.animate(withDuration: 1,
                       delay: 0.0,
                       options: [.curveLinear, .repeat, .autoreverse],
                       animations: {
                        self.alpha = 1.0
                        
        },
                       completion: nil)
    }
}
