// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NextensioAgent",
    platforms: [
        .macOS(.v10_14),
        .iOS(.v12)
    ],
    products: [
        .library(name: "NextensioAgent", targets: ["NextensioAgent"])
    ],
    dependencies: [],
    targets: [
        .target(
            name: "NextensioAgent",
            dependencies: ["NextensioGo"]
        ),
        .target(
            name: "NextensioGo",
            dependencies: [],
            exclude: [
                "go.sum",
                "apis.go",
                "Makefile"
            ],
            publicHeadersPath: ".",
            linkerSettings: [.linkedLibrary("nxt-go")]
        )
    ]
)
