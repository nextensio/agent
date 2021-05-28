//
//  AppDelegate.swift
//  NextensioAppMacOS
//
//  Created by Rudy Zulkarnain on 2/14/21.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    
    var statusBarItem: NSStatusItem!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        let statusBar = NSStatusBar.system
        statusBarItem = statusBar.statusItem(
            withLength: 9)
        statusBarItem.button?.title = "Nextensio"

        let statusBarMenu = NSMenu(title: "Uninstall")
        statusBarItem.menu = statusBarMenu

        statusBarMenu.addItem(
            withTitle: "Uninstall Nextensio system extension",
            action: #selector(SignInViewController.Uninstall),
            keyEquivalent: "")
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

