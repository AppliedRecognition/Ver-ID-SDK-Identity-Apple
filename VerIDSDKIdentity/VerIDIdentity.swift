//
//  VerIDIdentity.swift
//  VerIDIdentity
//
//  Created by Jakub Dolejs on 20/02/2020.
//  Copyright © 2020 Applied Recognition. All rights reserved.
//

import Foundation
import Security
import CertificateSigningRequest

/// Represents an identity of a client using Ver-ID SDK
/// - Since: 3.0.0
@available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *)
@objc public class VerIDIdentity: NSObject {
    
    public struct Options: OptionSet {
        public var rawValue: Int
        public static let overwriteKeychain = Options(rawValue: 1 << 0)
        public static let downloadLatest = Options(rawValue: 1 << 1)
        public static let autoRenew = Options(rawValue: 1 << 2)
        
        public static let `default`: Options = .autoRenew
        
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }
    }
    
    /// Digital certificate associated with this identity
    /// - Since: 1.0.0
    @objc public var certificate: SecCertificate {
        if let cert = self.keychain.certificate {
            return cert
        }
        fatalError()
    }
    /// Common name from the identity's digital certificate
    /// - Since: 1.0.0
    @objc public let commonName: String
    /// Default algorithm used when creating digital signatures
    /// - Since: 1.0.0
    @objc public let defaultSignatureAlgorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
    
    let renewalInterval: TimeInterval = 30 * 24 * 60 * 60
    var renewalURL: URL = URL(string: "https://licensing.ver-id.com")!
    private let keychain: Keychain
    
    /// Initializer
    /// - Parameters:
    ///   - url: URL of p12 file containing the digital certificate and private key used to construct the Ver-ID SDK identity
    ///   - password: Password to unlock the p12 file
    /// - Since: 2.0.0
    @objc public convenience init(url: URL?, password: String?) throws {
        try self.init(url: url, password: password, options: .default)
    }
    
    public convenience init(url: URL?, password: String?, options: Options = .default) throws {
        let p12url: URL
        if let `url` = url {
            p12url = url
        } else if let `url` = Bundle.main.url(forResource: "Ver-ID identity", withExtension: "p12") {
            p12url = url
        } else {
            throw IdentityError.missingIdentityFile
        }
        let p12Password: String
        if let pwd = password {
            p12Password = pwd
        } else if let pwd = Bundle.main.object(forInfoDictionaryKey: "com.appliedrec.verid.password") as? String {
            p12Password = pwd
        } else {
            throw IdentityError.missingPassword
        }
        let options = [kSecImportExportPassphrase as String: p12Password]
        let data = try Data(contentsOf: p12url) as CFData
        var rawItems: CFArray?
        let status = SecPKCS12Import(data, options as CFDictionary, &rawItems)
        guard status == errSecSuccess else {
            throw IdentityError.pkcs12ImportFailed
        }
        let items = rawItems! as! Array<Dictionary<String, Any>>
        guard let input = items.first else {
            throw IdentityError.identityIsEmpty
        }
        guard let identity = input[kSecImportItemIdentity as String] else {
            throw IdentityError.missingIdentityInDictionary
        }
        try self.init(identity: identity as! SecIdentity)
    }
    
    /// Initializer
    /// - Parameter url: URL of p12 file containing the digital certificate and private key used to construct the Ver-ID SDK identity
    /// - Since: 2.0.0
    @objc public convenience init(url: URL) throws {
        try self.init(url: url, password: nil)
    }
    
    public convenience init(url: URL, options: Options) throws {
        try self.init(url: url, password: nil, options: options)
    }
    
    /// Initializer
    /// - Parameter password: Password to unlock the p12 file
    /// - Since: 2.0.0 
    @objc public convenience init(password: String) throws {
        try self.init(url: nil, password: password, options: .default)
    }
    
    public convenience init(password: String, options: Options) throws {
        try self.init(url: nil, password: password, options: options)
    }
    
    /// Initializer
    /// - Parameter identity: Secure framework identity used to construct Ver-ID SDK identity
    /// - Since: 1.0.0
    @objc public convenience init(identity: SecIdentity) throws {
        try self.init(identity: identity, options: .default)
    }
    
    public convenience init(identity: SecIdentity, options: Options = .default) throws {
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let leafCert = cert else {
            throw IdentityError.failedToCopyCertificate
        }
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let privateKey = key else {
            throw IdentityError.failedToCopyPrivateKey
        }
        try self.init(certificate: leafCert, privateKey: privateKey, options: options)
    }
    
    public init(certificate: SecCertificate, privateKey: SecKey, options: Options = .default) throws {
        guard let cn = certificate.commonName else {
            throw CertificateError.failedToCopyCommonName
        }
        self.commonName = cn
        self.keychain = Keychain(identifier: cn)
        super.init()
        if options.contains(.overwriteKeychain) {
            self.keychain.clear()
        }
        self.keychain.privateKey = privateKey
        self.keychain.certificate = certificate
        if self.expiresSoon && (options.contains(.downloadLatest) || options.contains(.autoRenew)) {
            Task {
                do {
                    if options.contains(.autoRenew) && certificate.isRenewable {
                        try await self.renewCertificate()
                    } else {
                        try await self.downloadLatestCertificate()
                    }
                } catch {
                    NSLog("Failed to download latest certificate: \(error)")
                }
            }
        }
    }
    
    /// Sign a message
    /// - Parameters:
    ///   - message: Message to sign
    ///   - algorithm: Algorithm to use when creating the signature (defaults to `SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256`)
    /// - Returns: Signature
    /// - Since: 1.0.0
    @objc public func sign(_ message: Data, algorithm: SecKeyAlgorithm? = nil) throws -> Data {
        guard let key = self.keychain.privateKey else {
            throw KeyError.failedToReadPrivateKeyFromKeychain
        }
        let algo = algorithm ?? self.defaultSignatureAlgorithm
        guard SecKeyIsAlgorithmSupported(key, .sign, algo) else {
            throw KeyError.unsupportedAlgorithm
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algo, message as CFData, &error) else {
            if let err = error {
                throw err.takeRetainedValue()
            }
            throw KeyError.failedToCreateSignature
        }
        return signature as Data
    }
    
    @objc public func evaluateTrust(anchorCertificates: [SecCertificate]) throws {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates([self.certificate] as CFTypeRef, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, trust != nil else {
            throw IdentityError.failedToCreateTrust
        }
        SecTrustSetAnchorCertificates(trust!, anchorCertificates as CFArray)
        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust!, &error)
        if !trusted {
            if let err = error {
                throw err
            } else {
                throw IdentityError.certificateNotTrusted
            }
        }
    }
    
    private func reset() throws {
        self.keychain.clear()
    }
    
    private var expiresSoon: Bool {
        guard let expiryDate = self.certificate.expiryDate else {
            return false
        }
        return expiryDate.timeIntervalSinceNow < self.renewalInterval
    }
    
    private func ensurePublicKeyInCertificate(_ certificate: SecCertificate, matchesPublicKeyOfPrivateKey privateKey: SecKey) throws {
        guard let certPublicKey = certificate.publicKey, let keyPublicKey = SecKeyCopyPublicKey(privateKey), certPublicKey == keyPublicKey else {
            throw CertificateError.publicKeyDoesNotMatchRegisteredKey
        }
    }
    
    private func ensureValidSubjectInCertificate(_ certificate: SecCertificate) throws {
        guard let subject = certificate.commonName, subject == self.commonName else {
            throw CertificateError.invalidCertificateSubject
        }
    }
    
    private func certificate(_ cert1: SecCertificate, expiresAfter cert2: SecCertificate) -> Bool {
        guard let cert1ExpiryDate = cert1.expiryDate, let cert2ExpiryDate = cert2.expiryDate else {
            return false
        }
        return cert1ExpiryDate.compare(cert2ExpiryDate) == .orderedDescending
    }
    
    private func certificate(_ cert1: SecCertificate, hasSamePublicKeyAs cert2: SecCertificate) -> Bool {
        guard let cert1PublicKey = cert1.publicKey, let cert2PublicKey = cert2.publicKey else {
            return false
        }
        return cert1PublicKey == cert2PublicKey
    }
    
    public func downloadLatestCertificate() async throws {
        let url = self.renewalURL.appendingPathComponent("api").appendingPathComponent("certificates").appendingPathComponent(self.commonName)
        let (data, response) = try await URLSession.shared.data(from: url)
        let certificate = try self.certificateFromHttpResponse(response, data: data)
        if self.certificate(certificate, expiresAfter: self.certificate) {
            self.keychain.certificate = certificate
        }
    }
    
    public func renewCertificate() async throws {
        guard self.certificate.isRenewable else {
            return
        }
        let csr = try self.createRenewalCSR()
        let url = self.renewalURL.appendingPathComponent("api").appendingPathComponent("certificates").appendingPathComponent(self.commonName)
        var request = URLRequest(url: url)
        request.httpMethod = "post"
        request.httpBody = csr.data(using: .utf8)!
        let (data, response) = try await URLSession.shared.data(for: request)
        let certificate = try self.certificateFromHttpResponse(response, data: data)
        if self.certificate(certificate, expiresAfter: self.certificate) {
            self.keychain.certificate = certificate
        }
    }
    
    private func certificateFromHttpResponse(_ response: URLResponse, data: Data) throws -> SecCertificate {
        guard let statusCode = (response as? HTTPURLResponse)?.statusCode, statusCode < 400, let pem = String(data: data, encoding: .utf8) else {
            throw IOError.downloadFailed
        }
        guard let certificate = try SecCertificate.certificatesFromPEMString(pem).sorted(by: { cert1, cert2 in
            self.certificate(cert1, expiresAfter: cert2)
        }).first(where: { cert in
            self.certificate(cert, hasSamePublicKeyAs: self.certificate)
        }) else {
            throw CertificateError.failedToCreateCertificateFromData
        }
        return certificate
    }
    
    private func createRenewalCSR() throws -> String {
        guard let publicKey = self.certificate.publicKey else {
            throw IdentityError.failedToExtractPublicKey
        }
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            if let err = error {
                throw err.takeRetainedValue()
            }
            throw KeyError.failedToCopyExternalRepresentation
        }
        guard let privateKey = self.keychain.privateKey else {
            throw KeyError.failedToReadPrivateKeyFromKeychain
        }
        guard let privateKeyAttributes = SecKeyCopyAttributes(privateKey) as? [String:Any] else {
            throw KeyError.failedToCopyAttributes
        }
        guard Int(privateKeyAttributes[kSecAttrKeyType as String] as! String) == Int(kSecAttrKeyTypeRSA as String) else {
            throw KeyError.nonRSAPrivateKey
        }
        let keySizeBits = privateKeyAttributes[kSecAttrKeySizeInBits as String] as! Int
        if keySizeBits > 2048 {
            throw KeyError.keyTooLong
        }
        let csr = CertificateSigningRequest(keyAlgorithm: .rsa(signatureType: .sha256))
        csr.addSubjectItem(.commonName(self.commonName))
        guard let data = csr.buildCSRAndReturnString(keyData as Data, privateKey: privateKey, publicKey: publicKey) else {
            throw IdentityError.failedToCreateCertificateSigningRequest
        }
        return data
    }
}
