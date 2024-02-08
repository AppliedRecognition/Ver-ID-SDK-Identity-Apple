//
//  Errors.swift
//  VerIDLicence
//
//  Created by Jakub Dolejs on 20/02/2020.
//  Copyright © 2020 Applied Recognition. All rights reserved.
//

import Foundation

/// Errors thrown when converting strings and data
/// - Since: 1.0.0
@objc public enum ConversionError: Int, Error {
    /// Failed to convert base64-encoded string to data
    /// - Since: 1.0.0
    case failedToDecodeBase64String
}

/// Errors related to digital certificates
/// - Since: 1.0.0
@objc public enum CertificateError: Int, Error {
    /// Failed to create a digital certificate from data
    /// - Since: 1.0.0
    case failedToCreateCertificateFromData
    /// Failed to copy common name from digital certificate
    /// - Since: 1.0.0
    case failedToCopyCommonName
    /// Public key in certificate does not match public key of given private key
    /// - Since: 3.1.0
    case publicKeyDoesNotMatchRegisteredKey
    /// Invalid certificate subject – must match registered certificate
    /// - Since: 3.1.0
    case invalidCertificateSubject
    case failedToDeleteCertificateFromKeychain
    case failedToSaveCertificateInKeychain
    case failedToCopyPublicKey
    case missingExpiryDate
    case failedToFindIssuer
    case expiresBeforeCurrentCertificate
}

/// Errors related to digital identity
/// - Since: 1.0.0
@objc public enum IdentityError: Int, Error {
    /// Failed to import identity from a P12 file
    /// - Since: 1.0.0
    case pkcs12ImportFailed
    /// Identity object holds no records
    /// - Since: 1.0.0
    case identityIsEmpty
    /// Identity is missing in the raw records dictionary
    /// - Since: 1.0.0
    case missingIdentityInDictionary
    /// Failed to copy certificate from identity
    /// - Since: 1.0.0
    case failedToCopyCertificate
    /// Failed to copy private key from identity
    /// - Since: 1.0.0
    case failedToCopyPrivateKey
    /// Missing password to unlock p12 identity file
    /// - Since: 1.0.0
    case missingPassword
    /// Missing p12 identity file
    /// - Since: 1.0.0
    case missingIdentityFile
    /// Failed to extract public key from certificate
    /// - Since: 3.1.0
    case failedToExtractPublicKey
    /// Failed to create a certificate signing request
    /// - Since: 3.1.0
    case failedToCreateCertificateSigningRequest
    case failedToCreateTrust
    case certificateNotTrusted
    case invalidURL
    case unsupportedLicenceFileVersion
    case failedToReadPassword
}

/// Errors related to cryptographic key operations
/// - Since: 1.0.0
@objc public enum KeyError: Int, Error {
    /// The signing algorithm is not supported by the current version of the operating system
    /// - Since: 1.0.0
    case unsupportedAlgorithm
    /// Failed to create a digital signature
    /// - Since: 1.0.0
    case failedToCreateSignature
    /// Failed to copy external representation of the key
    /// - Since: 3.1.0
    case failedToCopyExternalRepresentation
    /// Failed to copy key attributes
    /// - Since: 3.1.0
    case failedToCopyAttributes
    /// Invalid private key type (expected RSA)
    /// - Since: 3.1.0
    case nonRSAPrivateKey
    /// The private key is too long (max supported size in bits = 2048)
    /// - Since: 3.1.0
    case keyTooLong
    /// Failed to save private key in keychain
    /// - Since: 3.1.0
    case failedToSavePrivateKeyInKeychain
    /// Failed to read private key from keychain
    /// - Since: 3.1.0
    case failedToReadPrivateKeyFromKeychain
    case failedToDeletePrivateKeyFromKeychain
    case failedToCopyPublicKeyFromPrivateKey
    case failedToCreatePrivateKey
}

@objc public enum IOError: Int, Error {
    case downloadFailed
}
