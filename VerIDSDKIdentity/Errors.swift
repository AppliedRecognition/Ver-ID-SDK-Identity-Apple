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
}
