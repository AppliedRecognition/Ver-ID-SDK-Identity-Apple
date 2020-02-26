//
//  VerIDClientIdentity.swift
//  VerIDClientIdentity
//
//  Created by Jakub Dolejs on 20/02/2020.
//  Copyright © 2020 Applied Recognition. All rights reserved.
//

import Foundation
import Security

/// Represents an identity of a client using Ver-ID SDK
/// - Since: 1.0.0
@objc public class VerIDSDKIdentity: NSObject {
    
    private let identity: SecIdentity
    /// Digital certificate associated with this identity
    /// - Since: 1.0.0
    @objc public let certificate: SecCertificate
    /// Common name from the identity's digital certificate
    /// - Since: 1.0.0
    @objc public let commonName: String
    /// Default algorithm used when creating digital signatures
    /// - Since: 1.0.0
    @objc public let defaultSignatureAlgorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
    
    /// Initializer
    /// - Parameters:
    ///   - url: URL of p12 file containing the digital certificate and private key used to construct the Ver-ID SDK identity
    ///   - password: Password to unlock the p12 file
    /// - Since: 2.0.0
    @objc public convenience init(url: URL?, password: String?) throws {
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
    
    /// Initializer
    /// - Parameter password: Password to unlock the p12 file
    /// - Since: 2.0.0 
    @objc public convenience init(password: String) throws {
        try self.init(url: nil, password: password)
    }
    
    /// Initializer
    /// - Parameter identity: Secure framework identity used to construct Ver-ID SDK identity
    /// - Since: 1.0.0
    @objc public init(identity: SecIdentity) throws {
        self.identity = identity
        var cert: SecCertificate?
        guard SecIdentityCopyCertificate(self.identity, &cert) == errSecSuccess, let leafCert = cert else {
            throw IdentityError.failedToCopyCertificate
        }
        self.certificate = leafCert
        guard let cn = self.certificate.commonName else {
            throw CertificateError.failedToCopyCommonName
        }
        self.commonName = cn
    }
    
    /// Sign a message
    /// - Parameters:
    ///   - message: Message to sign
    ///   - algorithm: Algorithm to use when creating the signature (defaults to `SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256`)
    /// - Returns: Signature
    /// - Since: 1.0.0
    @objc public func sign(_ message: Data, algorithm: SecKeyAlgorithm? = nil) throws -> Data {
        var privateKey: SecKey?
        guard SecIdentityCopyPrivateKey(self.identity, &privateKey) == errSecSuccess, let key = privateKey else {
            throw IdentityError.failedToCopyPrivateKey
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
}
