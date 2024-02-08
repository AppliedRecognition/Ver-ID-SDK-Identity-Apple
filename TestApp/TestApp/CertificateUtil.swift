//
//  CertificateUtil.swift
//  TestApp
//
//  Created by Jakub Dolejs on 15/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import Foundation
import Security
import ShieldSecurity
import ShieldX509
import ShieldPKCS
import PotentASN1

class CertificateUtil {
    
    static var serialNumber: Int64 = 1
    
    static func generateCertificate(commonName: String, publicKey: SecKey, signingKey: SecKey, issuerCommonName: String = "com.appliedrec.ver-id.standalone", expiryDays: Int = 7) throws -> SecCertificate {
        let expiryDate = Date().addingTimeInterval(Double(expiryDays) * 24 * 60 * 60)
        let publicKeyBytes = try publicKey.encode()
        let serialNumber = TBSCertificate.SerialNumber(integerLiteral: CertificateUtil.serialNumber)
        let issuer = try NameBuilder().add(issuerCommonName, forTypeName: "CN").name
        let subject = try NameBuilder().add(commonName, forTypeName: "CN").name
        let subjectPublicKey = BitString(bytes: publicKeyBytes)
        let algorithmIdentifier = try AlgorithmIdentifier(publicKey: publicKey)
        let subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithm: algorithmIdentifier, subjectPublicKey: subjectPublicKey)
        let notAfter = AnyTime(date: expiryDate, timeZone: .gmt)
        guard let cert = try Certificate.Builder(
            serialNumber: serialNumber,
            issuer: issuer,
            subject: subject,
            subjectPublicKeyInfo: subjectPublicKeyInfo,
            notAfter: notAfter)
                .build(signingKey: signingKey, digestAlgorithm: .sha256).sec() else {
            throw "Failed to create certificate"
        }
        CertificateUtil.serialNumber += 1
        return cert
    }
}
