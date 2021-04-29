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
    var authFlowCoordinator: AuthFlowCoordinator?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        print("AppDelegate application")
        authFlowCoordinator = AuthFlowCoordinator.instantiate()
        window?.rootViewController = authFlowCoordinator?.rootViewController

        return true
    }
    
    func applicationWillTerminate(_ application: UIApplication) {
        print("application will terminate")
        authFlowCoordinator?.handleTerminateAuthView()
    }
    
    func applicationWillEnterForeground(_ application: UIApplication) {
        print("application will enter foreground")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: UIApplication) -> Bool {
        print("appShouldTerminateAfterLastWindowClosed")
        return true
    }
    
//    // MARK: UISceneSession Lifecycle
//
//    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
//        // Called when a new scene session is being created.
//        // Use this method to select a configuration to create the new scene with.
//        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
//    }
//
//    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
//        // Called when the user discards a scene session.
//        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
//        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
//    }


}

