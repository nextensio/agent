//
//  AppDelegate.swift
//  NextensioAgent
//
//  Created by Rudy Zulkarnain on 2/7/21.
//

import UIKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let controller = AuthBaseViewController.instantiate(storyBoardName: "SignIn",
                                           viewControllerIdentifier: "SignIn") as! AuthBaseViewController
        window?.rootViewController = controller;
        return true
    }
    
    func applicationWillTerminate(_ application: UIApplication) {
        print("app will terminate")
    }
    
    func applicationWillEnterForeground(_ application: UIApplication) {
        print("app will enter foreground")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: UIApplication) -> Bool {
        print("app should terminate after last window closed")
        return true
    }
    
    func applicationDidEnterBackground(_ application: UIApplication) {
        print("app did enter backgroud")
    }
}
