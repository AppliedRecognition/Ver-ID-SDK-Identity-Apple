// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Ver-ID-SDK-Identity",
    platforms: [
        .macOS(.v10_13),
        .iOS(.v10)],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "VerIDSDKIdentity",
            targets: ["VerIDSDKIdentity"]),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "VerIDSDKIdentity",
            path: "VerIDSDKIdentity",
            exclude: ["MacOS-Info.plist", "Info.plist"])
    ]
)
