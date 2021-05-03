//
//  TunnelViewController.swift
//  NextensioAgent
//
//  Created by Rudy Zulkarnain on 2/7/21.
//
import UIKit
import OktaAuthSdk

class TunnelViewController: AuthBaseViewController {

    @IBOutlet weak var connectButton: UIButton!
    @IBOutlet weak var signInButton: UIButton!

    override func viewDidLoad() {
        super.viewDidLoad()

        self.navigationItem.title = "Nextensio Tunnel"
        
        // Direct Tunnel Provider
        tunnelProvider = TunnelProvider(button: connectButton, state: nil, direct: true)
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func connectDirect(_ sender: UIButton) {
        print("connect direct")
        if (sender.title(for: .normal) == "Connect Direct") {
            tunnelProvider?.connectDirect()
            signInButton.isEnabled = false;
        } else {
            tunnelProvider?.disconnectDirect()
            signInButton.isEnabled = true;
        }
    }
    
    @IBAction func connectTunnel(_ sender: Any) {
        print("connect tunnel")
        self.flowCoordinatorDelegate?.onInitAuthentication(status: self.status)
    }
}

