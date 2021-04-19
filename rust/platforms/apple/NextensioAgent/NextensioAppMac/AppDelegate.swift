//
//  AppDelegate.swift
//  NextensioAppMacOS
//
//  Created by Rudy Zulkarnain on 2/14/21.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Insert code here to initialize your application
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        print("application will terminate")
    }

    func applicationWillResignActive(_ aNotification: Notification) { }

    func applicationDidEnterBackground(_ aNotification: Notification) { }

    func applicationWillEnterForeground(_ aNotification: Notification) { }

    func applicationDidBecomeActive(_ aNotification: Notification) { }
    
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

