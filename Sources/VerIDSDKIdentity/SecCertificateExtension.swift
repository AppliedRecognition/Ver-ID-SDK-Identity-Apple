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
import ASN1Decoder

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
        if data.count > 8 {
            return nil
        }
        var paddedData = [UInt8](repeating: 0, count: 8)
        for i in 0..<data.count {
            paddedData[i] = data[i]
        }
        paddedData.reverse()
        let value: UInt64 = paddedData.withUnsafeBytes { $0.load(as: UInt64.self) }
        return UInt64(bigEndian: value)
    }
    
    var expiryDate: Date? {
        //        guard let summary = SecCertificateCopySubjectSummary(self) as? String else {
        //            return nil
        //        }
        //        let scanner = Scanner(string: summary)
        //        guard scanner.scanUpToString("Not After ") != nil && scanner.scanString("Not After ") != nil, let expiryDateStr = scanner.scanUpToString(" GMT") else {
        //            return nil
        //        }
        //        let dateFormatter = DateFormatter()
        //        dateFormatter.dateFormat = "MMM dd HH:mm:ss yyyy"
        //        guard let expiryDate = dateFormatter.date(from: expiryDateStr) else {
        //            return nil
        //        }
        //        return expiryDate
        let data = SecCertificateCopyData(self) as Data
        guard let cert = try? X509Certificate(der: data) else {
            return nil
        }
        return cert.notAfter
    }
    
    var issuer: CA {
        get throws {
            let data = SecCertificateCopyData(self) as Data
            let cert = try X509Certificate(data: data)
            guard let issuer = cert.issuerDistinguishedName else {
                throw CertificateError.failedToFindIssuer
            }
            let pattern = #"CN=([^,]+)"#
            let regex = try NSRegularExpression(pattern: pattern)
            let results = regex.matches(in: issuer, range: NSRange(issuer.startIndex..., in: issuer))
            for result in results {
                if let range = Range(result.range(at: 1), in: issuer) {
                    let match = String(issuer[range])
                    guard let ca = CA(rawValue: match) else {
                        throw CertificateError.failedToFindIssuer
                    }
                    return ca
                }
            }
            throw CertificateError.failedToFindIssuer
        }
    }
    
    var isRenewable: Bool {
        guard let issuer = try? self.issuer else {
            return false
        }
        return issuer == .standalone || issuer == .reporting
    }
    
    func expiresAfter(_ certificate: SecCertificate) -> Bool {
        guard let cert1ExpiryDate = self.expiryDate, let cert2ExpiryDate = certificate.expiryDate else {
            return false
        }
        return cert1ExpiryDate.compare(cert2ExpiryDate) == .orderedDescending
    }
    
    func hasSamePublicKey(as certificate: SecCertificate) -> Bool {
        guard let cert1PublicKey = self.publicKey, let cert2PublicKey = certificate.publicKey else {
            return false
        }
        return cert1PublicKey == cert2PublicKey
    }
    
    func publicKeyMatchesPrivateKey(_ privateKey: SecKey) -> Bool {
        guard let certPublicKey = self.publicKey, let keyPublicKey = SecKeyCopyPublicKey(privateKey), certPublicKey == keyPublicKey else {
            return false
        }
        return true
    }
    
    func evaluateTrust(anchorCertificates: [SecCertificate]) throws {
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates([self] as CFTypeRef, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, trust != nil else {
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
    
//    var issuer: String? = {
//        let data = SecCertificateCopyData(cert) as Data
//        guard let decoded = try? ASN1Decoder(schema: Certificate.asn1Schema).decode(Certificate.self, from: data) else {
//            return nil
//        }
//        if let val = decoded.tbsCertificate.issuer.first(where: { $0.contains(where: { $0.type.fields == [2,5,4,3] }) })?.first(where: { $0.type.fields == [2,5,4,3] })?.value {
//            return "\(val)"
//        } else {
//            return nil
//        }
//    }()
    
    /// Extract digital certificates from a PEM-encoded string
    /// - Parameter pemString: PEM string with certificates
    /// - Since: 1.0.0
    static func certificatesFromPEMString(_ pemString: String) throws -> [SecCertificate] {
        let pattern = "-----BEGIN\\sCERTIFICATE-----\\s*([a-zA-Z0-9\\s\\/+]+=*)\\s*-----END\\sCERTIFICATE-----"
        let range = NSRange(location: 0, length: pemString.utf16.count)
        let regex = try! NSRegularExpression(pattern: pattern)
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
