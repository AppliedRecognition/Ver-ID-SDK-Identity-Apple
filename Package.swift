// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Ver-ID-SDK-Identity",
    platforms: [
        .macOS(.v10_13),
        .iOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/filom/ASN1Decoder.git", from: "1.0.0"),
        .package(url: "https://github.com/cbaker6/CertificateSigningRequest.git", from: "1.30.0")
    ],
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
            dependencies: [
                .product(name: "ASN1Decoder", package: "ASN1Decoder"),
                .product(name: "CertificateSigningRequest", package: "CertificateSigningRequest")
            ],
            path: "VerIDSDKIdentity",
            exclude: ["MacOS-Info.plist", "Info.plist"]
        )
    ]
)
