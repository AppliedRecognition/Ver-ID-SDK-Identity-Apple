//
//  TestRunner.swift
//  TestApp
//
//  Created by Jakub Dolejs on 11/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import Foundation
import Security
import VerIDSDKIdentity

final class TestRunner: ObservableObject {
    let correctPassword = "dummy"
    let commonName = "verid.client.identity"
    let identityFileURL = Bundle.main.url(forResource: "Ver-ID identity current", withExtension: "p12")!
    let expiredIdentityFileURL = Bundle.main.url(forResource: "Ver-ID identity expired", withExtension: "p12")!
    let certificateSerialNumber = 257
    var anchorCertificates: [SecCertificate] = []
    
    var tests: [TestSpec] = []
    @Published var testResults: [TestResult] = []
    @Published var runningTestName: String?
    
    public lazy var signingPrivateKey: SecKey? = {
        return try? self.createPrivateKey()
    }()
    
    public lazy var identityPrivateKey: SecKey? = {
        return try? self.createPrivateKey()
    }()
    
    private func createPrivateKey() throws -> SecKey {
        let keyParams: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyParams as CFDictionary, &error) else {
            if let err = error?.takeRetainedValue() {
                throw err
            }
            throw KeyError.failedToCreatePrivateKey
        }
        return privateKey
    }
    
    public func createCertificate(expiryDays: Int = 7, issuer: CA = .standalone) throws -> SecCertificate {
        guard let privateKey = self.identityPrivateKey else {
            throw KeyError.failedToCreatePrivateKey
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw KeyError.failedToCopyPublicKeyFromPrivateKey
        }
        guard let signingKey = self.signingPrivateKey else {
            throw KeyError.failedToCreatePrivateKey
        }
        let cert = try CertificateUtil.generateCertificate(commonName: self.commonName, publicKey: publicKey, signingKey: signingKey, issuerCommonName: issuer.rawValue, expiryDays: expiryDays)
        guard let certPublicKey = cert.publicKey, certPublicKey == publicKey else {
            throw "Cert public key must match the private key"
        }
        return cert
    }
    
    private func attributesOfPrivateKey(_ privateKey: SecKey) throws -> NSDictionary {
        if let dict = SecKeyCopyAttributes(privateKey) {
            return dict as NSDictionary
        }
        throw "Failed to copy key attributes"
    }
    
    private func createIdentity(expiryDays: Int = 7, options: VerIDIdentity.Options = .default, issuer: CA = .standalone) throws -> VerIDIdentity {
        guard let privateKey = self.identityPrivateKey else {
            throw KeyError.failedToCreatePrivateKey
        }
        let cert = try self.createCertificate(expiryDays: expiryDays, issuer: issuer)
        if let certPublicKey = try? cert.publicKey?.encode().base64EncodedString(), let privateKeyPublicKey = try? SecKeyCopyPublicKey(privateKey)?.encode().base64EncodedString() {
            if certPublicKey != privateKeyPublicKey {
                throw "Public key in certificate and private key must match"
            }
        }
        return try VerIDIdentity(certificate: cert, privateKey: privateKey, options: options)
    }
    
    init() {
        self.tests = [
            TestSpec("Create client", description: "Create an instance of identity client.") {
                _ = try self.createIdentity(options: .overwriteKeychain)
            },
            TestSpec("Fail without credentials", description: "Should fail to create an instance of identity client when URL and password are set to nil.") {
                do {
                    _ = try VerIDIdentity(url: nil, password: nil)
                } catch {
                    return
                }
                throw "Should not succeed"
            },
            TestSpec("Fail without password", description: "Should fail to create an instance of identity client without a password.") {
                do {
                    _ = try VerIDIdentity(url: self.identityFileURL, options: .overwriteKeychain)
                } catch {
                    return
                }
                throw "Should not succeed"
            },
            TestSpec("Fail with invalid password", description: "Should fail to create an instance of identity client with incorrect password.") {
                do {
                    _ = try VerIDIdentity(url: self.identityFileURL, password: "nonsense", options: .overwriteKeychain)
                } catch {
                    return
                }
                throw "Should not succeed"
            },
            TestSpec("Common name matches", description: "The common name in the identity client's licence certificate should match \(self.commonName).") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                if identity.commonName != self.commonName {
                    throw "Invalid CN: \(identity.commonName)"
                }
            },
            TestSpec("Sign message", description: "Use identity client to cryptographically sign a message.") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                let message = Data([UInt8](repeating: 0, count: 8))
                _ = try identity.sign(message)
            },
            TestSpec("Verify signature", description: "Verify a signature of a message signed by the identity client.") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                let message = Data([UInt8](repeating: 0, count: 8))
                let signature = try identity.sign(message)
                guard let key = identity.certificate.publicKey else {
                    throw "Missing public key"
                }
                var error: Unmanaged<CFError>?
                if !SecKeyVerifySignature(key, identity.defaultSignatureAlgorithm, message as CFData, signature as CFData, &error) {
                    if let err = error?.takeRetainedValue() {
                        throw err
                    }
                    throw "Invalid signature"
                }
            },
            TestSpec("Evaluate trust", description: "Evaluate trust in the identity client's certificate.") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                try identity.evaluateTrust(anchorCertificates: self.anchorCertificates)
            },
            TestSpec("Fail trust on expired cert", description: "Trust evaluation of the identity client's certificate should fail if the certificate is expired.") {
                let identity = try self.createIdentity(expiryDays: -1, options: .overwriteKeychain)
                guard let expiry = identity.certificate.expiryDate else {
                    throw "Certificate does not have an expiry date"
                }
                guard Date().compare(expiry) == .orderedDescending else {
                    let dateFormat = DateFormatter()
                    dateFormat.dateStyle = .medium
                    dateFormat.timeStyle = .none
                    throw "Certificate should have expired (actual expiry date \(dateFormat.string(from: expiry)))"
                }
                do {
                    try identity.evaluateTrust(anchorCertificates: self.anchorCertificates)
                } catch {
                    return
                }
                throw "Should fail on expired cert"
            },
            TestSpec("Get certificate serial number", description: "Get the serial number in the identity client's certificate. Should be \(self.certificateSerialNumber).") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                guard let serial = identity.certificate.serialNumber else {
                    throw "Failed to get serial number from certificate"
                }
                guard serial > 0 else {
                    throw "Invalid serial number (\(serial)), expected value greater than 0"
                }
            },
            TestSpec("Update certificate with older", description: "Create an identity, then create another instance with an older certificate. The new identity should have the newer cert") {
                let identity = try self.createIdentity(expiryDays: 30, options: .overwriteKeychain)
                let identity2 = try self.createIdentity(expiryDays: 10, options: [])
                guard let exp1 = identity.certificate.expiryDate, let exp2 = identity2.certificate.expiryDate else {
                    throw "Expiry not set"
                }
                guard exp1.compare(exp2) == .orderedSame else {
                    throw "Identity created with an older expiry date than a previous identity should inherit previous identity's certificate"
                }
            },
            TestSpec("Download latest certificate", description: "Download latest certificate and place it in keychain") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                guard let originalCertExpiry = identity.certificate.expiryDate else {
                    throw "Supplied certificate doesn't have an expiry date"
                }
                try await identity.downloadLatestCertificate()
                guard let newCertExpiry = identity.certificate.expiryDate else {
                    throw "Renewed certificate doesn't have an expiry date"
                }
                if newCertExpiry.compare(originalCertExpiry) != .orderedDescending {
                    throw "New certificate should expire after original"
                }
            },
            TestSpec("Renew certificate", description: "Request a certificate renewal") {
                let identity = try self.createIdentity(options: .overwriteKeychain)
                guard let originalCertExpiry = identity.certificate.expiryDate else {
                    throw "Supplied certificate doesn't have an expiry date"
                }
                try await identity.renewCertificate()
                guard let newCertExpiry = identity.certificate.expiryDate else {
                    throw "Renewed certificate doesn't have an expiry date"
                }
                if newCertExpiry.compare(originalCertExpiry) != .orderedDescending {
                    throw "New certificate should expire after original"
                }
            },
            TestSpec("Fail to renew evaluation licence", description: "Evaluation licence certificate should not be automatically renewed") {
                let identity = try self.createIdentity(options: .overwriteKeychain, issuer: .evaluation)
                guard let originalCertExpiry = identity.certificate.expiryDate else {
                    throw "Supplied certificate doesn't have an expiry date"
                }
                try await identity.renewCertificate()
                guard let newCertExpiry = identity.certificate.expiryDate else {
                    throw "Renewed certificate doesn't have an expiry date"
                }
                guard newCertExpiry.compare(originalCertExpiry) == .orderedSame else {
                    throw "New certificate should have the same expiry date as the old one"
                }
            },
            TestSpec("Fail with different key", description: "Fail to replace existing certificate with one that has a different public key") {
                let privateKey = try self.createPrivateKey()
                guard let signingKey = self.signingPrivateKey else {
                    throw KeyError.failedToCreatePrivateKey
                }
                let cert = try CertificateUtil.generateCertificate(commonName: self.commonName, publicKey: privateKey.publicKey!, signingKey: signingKey, issuerCommonName: CA.standalone.rawValue, expiryDays: 2)
                let identity = try VerIDIdentity(certificate: cert, privateKey: privateKey)
                do {
                    try await identity.downloadLatestCertificate()
                } catch {
                    return
                }
                throw "Certificate download should fail"
            }
        ]
        self.anchorCertificates = (try? self.createAnchorCertificates()) ?? []
    }
    
    public func runTest(_ test: TestSpec) async throws -> TestResult {
        await MainActor.run {
            self.runningTestName = test.id
        }
        let result: TestResult
        let date = Date()
        do {
            try await test.test()
            result = TestResult(spec: test, passed: true, comments: nil, date: date)
            NSLog("✅ %@ succeeded", test.id)
        } catch {
            result = TestResult(spec: test, passed: false, comments: error.localizedDescription, date: date)
            NSLog("❌ %@ failed: %@", test.id, error.localizedDescription)
        }
        await MainActor.run {
            self.runningTestName = nil
        }
        return result
    }
    
    public func runTests() async {
        await MainActor.run {
            self.testResults = []
        }
        for testSpec in self.tests {
            await MainActor.run {
                self.runningTestName = testSpec.id
            }
            let result: TestResult
            let date = Date()
            do {
                try await testSpec.test()
                result = TestResult(spec: testSpec, passed: true, comments: nil, date: date)
                NSLog("✅ %@ succeeded", testSpec.id)
            } catch {
                result = TestResult(spec: testSpec, passed: false, comments: error.localizedDescription, date: date)
                NSLog("❌ %@ failed: %@", testSpec.id, error.localizedDescription)
            }
            await MainActor.run {
                self.testResults.append(result)
            }
        }
        await MainActor.run {
            self.runningTestName = nil
        }
    }
    
    private func createAnchorCertificates() throws -> [SecCertificate] {
        guard let signingKey = self.signingPrivateKey else {
            throw KeyError.failedToCreatePrivateKey
        }
        guard let publicKey = SecKeyCopyPublicKey(signingKey) else {
            throw KeyError.failedToCopyPublicKeyFromPrivateKey
        }
        let anchor = try CertificateUtil.generateCertificate(commonName: "com.appliedrec.ver-id.standalone", publicKey: publicKey, signingKey: signingKey, issuerCommonName: "Ver-ID", expiryDays: 365)
        return [anchor]
    }
    
    private func certificatesFromPEMString(_ pemString: String) throws -> [SecCertificate] {
        let pattern = "-----BEGIN\\sCERTIFICATE-----((.|\\n)+?)-----END\\sCERTIFICATE-----"
        let range = NSRange(location: 0, length: pemString.utf16.count)
        let regex = try! NSRegularExpression(pattern: pattern, options: .allowCommentsAndWhitespace)
        let matches = regex.matches(in: pemString, options: [], range: range)
        return try matches.map({ result in
            let base64 = pemString[Range(result.range(at: 1), in: pemString)!].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let certData = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
                throw ConversionError.failedToDecodeBase64String
            }
            guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
                throw CertificateError.failedToCreateCertificateFromData
            }
            return cert
        })
    }
}


struct TestResult: Identifiable, Hashable, Equatable {
    var id: String {
        self.spec.id
    }
    let spec: TestSpec
    let passed: Bool
    let comments: String?
    let date: Date
}

struct TestSpec: Identifiable, Hashable, Equatable {
    static func == (lhs: TestSpec, rhs: TestSpec) -> Bool {
        lhs.id == rhs.id
    }
    
    let id: String
    let description: String
    let test: () async throws -> Void
    
    init(_ id: String, description: String, test: @escaping () async throws -> Void) {
        self.id = id
        self.description = description
        self.test = test
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(self.id)
        hasher.combine(self.description)
    }
}

fileprivate class ErrorWrapper {
    var error: Error?
}
