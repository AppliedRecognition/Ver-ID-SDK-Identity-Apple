//
//  SecCertificateExtension.swift
//  VerIDLicence
//
//  Created by Jakub Dolejs on 20/02/2020.
//  Copyright © 2020 Applied Recognition. All rights reserved.
//

import Foundation
import Security
import CommonCrypto

/// - Since: 1.0.0
@available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *)
public extension SecCertificate {
    
    /// Common name on the certificate
    /// - Since: 1.0.0
    var commonName: String? {
        var commonName: CFString?
        guard SecCertificateCopyCommonName(self, &commonName) == errSecSuccess, let name = commonName else {
            return nil
        }
        return name as String
    }
    
    /// Certificate's public key
    /// - Since: 1.0.0
    var publicKey: SecKey? {
        #if os(macOS)
        if #available(macOS 10.14, *) {
            return SecCertificateCopyKey(self)
        } else {
            var pk: SecKey?
            if SecCertificateCopyPublicKey(self, &pk) == errSecSuccess {
                return pk
            }
            return nil
        }
        #elseif !targetEnvironment(macCatalyst)
        if #available(iOS 12.0, macCatalyst 13.0, tvOS 12.0, watchOS 5.0, *) {
            return SecCertificateCopyKey(self)
        } else {
            return SecCertificateCopyPublicKey(self)
        }
        #else
        return SecCertificateCopyKey(self)
        #endif
    }
    
    /// Certificate fingerprint as SHA256 hash
    /// - Since: 1.0.0
    var fingerprint: Data {
        let certData = SecCertificateCopyData(self) as Data
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256([UInt8](certData), CC_LONG(certData.count), &digest)
        return Data(digest)
    }
    
    /// Find certificate's issuer certificate among an array of certificates
    /// - Parameter certificates: Authority certificates in which to look for an issuer
    /// - Since: 1.0.0
    func findIssuer(among certificates: [SecCertificate]) -> SecCertificate? {
        guard let issuer = SecCertificateCopyNormalizedIssuerSequence(self) else {
            return nil
        }
        return certificates.compactMap({
            guard let subject = SecCertificateCopyNormalizedSubjectSequence($0) else {
                return nil
            }
            if subject == issuer {
                return $0
            } else {
                return nil
            }
        }).first
    }
    
    /// Get certificate serial number
    /// - Since: 1.0.0
    var serialNumber: UInt64? {
        let cfData: CFData
        #if os(iOS)
        if #available(iOS 11.0, macCatalyst 11.0, *) {
            guard let d = SecCertificateCopySerialNumberData(self, nil) else {
                return nil
            }
            cfData = d
        } else {
            #if !targetEnvironment(macCatalyst)
            guard let d = SecCertificateCopySerialNumber(self) else {
                return nil
            }
            cfData = d
            #else
            return nil
            #endif
        }
        #else
        guard let d = SecCertificateCopySerialNumberData(self, nil) else {
            return nil
        }
        cfData = d
        #endif
        let data = cfData as Data
        var bytes = [UInt8](repeating: 0, count: 8)
        var j = 0
        for i in (8-data.count)..<8 {
            bytes[i] = data[j]
            j += 1
        }
        let value = UnsafePointer(bytes).withMemoryRebound(to: UInt64.self, capacity: 1) {
            $0.pointee
        }
        return UInt64(bigEndian: value)
    }
    
    /// Extract digital certificates from a PEM-encoded string
    /// - Parameter pemString: PEM string with certificates
    /// - Since: 1.0.0
    static func certificatesFromPEMString(_ pemString: String) throws -> [SecCertificate] {
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
