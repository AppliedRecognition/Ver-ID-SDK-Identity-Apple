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
        try self.init(url: url, password: password, overwriteExisting: false)
    }
    
    public convenience init(url: URL?, password: String?, overwriteExisting: Bool = false) throws {
        let licenceURL: URL
        if let `url` = url {
            if url.pathExtension.lowercased() == "identity" || url.pathExtension.lowercased() == "p12" {
                licenceURL = url
            } else {
                throw IdentityError.invalidURL
            }
        } else if let url = Bundle.main.url(forResource: "Ver-ID identity", withExtension: "p12") {
            licenceURL = url
        } else if let url = Bundle.main.url(forResource: "Ver-ID", withExtension: "identity") {
            licenceURL = url
        } else {
            throw IdentityError.missingIdentityFile
        }
        let p12Data: Data
        let p12Password: String
        if licenceURL.pathExtension == "identity" {
            let licenceData = try Data(contentsOf: licenceURL)
            let version: UInt32 = UInt32(littleEndian: licenceData[0..<4].withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) })
            if version != 1 {
                throw IdentityError.unsupportedLicenceFileVersion
            }
            let p12Length: UInt32 = licenceData[4..<8].withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) }
            let passwordLength: UInt32 = licenceData[8..<12].withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) }
            p12Data = Data(licenceData[12..<12+p12Length])
            guard let password = String(data: Data(licenceData[12+p12Length..<12+p12Length+passwordLength]), encoding: .utf8) else {
                throw IdentityError.failedToReadPassword
            }
            p12Password = password
        } else {
            p12Data = try Data(contentsOf: licenceURL)
            if let pwd = password {
                p12Password = pwd
            } else if let pwd = Bundle.main.object(forInfoDictionaryKey: "com.appliedrec.verid.password") as? String {
                p12Password = pwd
            } else {
                throw IdentityError.missingPassword
            }
        }
        let options = [kSecImportExportPassphrase as String: p12Password]
        var rawItems: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &rawItems)
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
    
    public convenience init(url: URL, overwriteExisting: Bool) throws {
        try self.init(url: url, password: nil, overwriteExisting: overwriteExisting)
    }
    
    /// Initializer
    /// - Parameter password: Password to unlock the p12 file
    /// - Since: 2.0.0 
    @objc public convenience init(password: String) throws {
        try self.init(url: nil, password: password, overwriteExisting: false)
    }
    
    public convenience init(password: String, overwriteExisting: Bool) throws {
        try self.init(url: nil, password: password, overwriteExisting: overwriteExisting)
    }
    
    /// Initializer
    /// - Parameter identity: Secure framework identity used to construct Ver-ID SDK identity
    /// - Since: 1.0.0
    @objc public convenience init(identity: SecIdentity) throws {
        try self.init(identity: identity, overwriteExisting: false)
    }
    
    public convenience init(identity: SecIdentity, overwriteExisting: Bool=false) throws {
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let leafCert = cert else {
            throw IdentityError.failedToCopyCertificate
        }
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let privateKey = key else {
            throw IdentityError.failedToCopyPrivateKey
        }
        try self.init(certificate: leafCert, privateKey: privateKey, overwriteExisting: overwriteExisting)
    }
    
    public init(certificate: SecCertificate, privateKey: SecKey, overwriteExisting: Bool=false) throws {
        guard let cn = certificate.commonName else {
            throw CertificateError.failedToCopyCommonName
        }
        self.commonName = cn
        self.keychain = Keychain(identifier: cn)
        super.init()
        if overwriteExisting {
            self.keychain.clear()
        }
        self.keychain.privateKey = privateKey
        self.keychain.certificate = certificate
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
    
    /// Update identity certificate
    ///
    /// The new certificate must have the same public key as the current certificate and must expire after the current certificate.
    /// - Parameter certificate: Certificate replacing the existing one
    /// - Since: 3.1.0
    public func updateCertificate(_ certificate: SecCertificate) throws {
        let existingCert = self.certificate
        guard certificate.expiresAfter(existingCert) else {
            throw CertificateError.expiresBeforeCurrentCertificate
        }
        guard certificate.hasSamePublicKey(as: existingCert) else {
            throw CertificateError.publicKeyDoesNotMatchRegisteredKey
        }
        self.keychain.certificate = certificate
    }
    
    private func reset() throws {
        self.keychain.clear()
    }
    
    /// Create a certificate signing request (CSR) to renew the identity
    /// - Returns: String with PEM encoded certificat esigning request
    /// - Since: 3.1.0
    public func createRenewalCSR() throws -> String {
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
