//
//  VerIDLicenceTests.swift
//  VerIDLicenceTests
//
//  Created by Jakub Dolejs on 20/02/2020.
//  Copyright © 2020 Applied Recognition. All rights reserved.
//

import XCTest
import Security
@testable import VerIDSDKIdentity

class VerIDLicenceTests: XCTestCase {
    
    let correctPassword = "dummy"
    let commonName = "verid.client.identity"

    func testCreateClient_failMissingCredentials() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        XCTAssertThrowsError(try VerIDIdentity(url: nil, password: nil))
    }
    
    func testCreateClient_succeeds() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            XCTAssertNoThrow(try VerIDIdentity(url: url, password: self.correctPassword))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateClient_failMissingPassword() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            XCTAssertThrowsError(try VerIDIdentity(url: url))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateClient_failMissingIdentityFile() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        XCTAssertThrowsError(try VerIDIdentity(password: self.correctPassword))
    }
    
    func testCreateClient_failInvalidPassword() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            XCTAssertThrowsError(try VerIDIdentity(url: url, password: "nonsense"))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateIdentityFromRemoteURL_succeeds() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        guard let url = URL(string: "https://ver-id.s3.us-east-1.amazonaws.com/ios/com.appliedrec.verid.licenceclient/test_assets/Ver-ID%20identity.p12") else {
            XCTFail()
            return
        }
        XCTAssertNoThrow(try VerIDIdentity(url: url, password: self.correctPassword))
    }
    
    func testClientCommonName_matches() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDIdentity(url: url, password: self.correctPassword)
            XCTAssertEqual(self.commonName, identity.commonName)
        } catch {
            XCTFail()
        }
    }
    
    func testSignMessage_succeeds() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDIdentity(url: url, password: self.correctPassword)
            let message = Data([UInt8](repeating: 0, count: 8))
            XCTAssertNoThrow(try identity.sign(message))
        } catch {
           XCTFail()
       }
    }
    
    func testVerifySignature_succeeds() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDIdentity(url: url, password: self.correctPassword)
            let message = Data([UInt8](repeating: 0, count: 8))
            let signature = try identity.sign(message)
            guard let key = identity.certificate.publicKey else {
                XCTFail()
                return
            }
            XCTAssertTrue(SecKeyVerifySignature(key, identity.defaultSignatureAlgorithm, message as CFData, signature as CFData, nil))
        } catch {
            XCTFail()
        }
    }
    
    func testEvaluateTrust_succeeds() {
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDIdentity(url: url, password: self.correctPassword)
            guard let certsURL = URL(string: "https://dev.ver-id.com/licensing/certs") else {
                XCTFail()
                return
            }
            let pemData = try Data(contentsOf: certsURL)
            guard let pemString = String(data: pemData, encoding: .utf8) else {
                XCTFail()
                return
            }
            var certs = try self.certificatesFromPEMString(pemString)
            XCTAssertGreaterThan(certs.count, 0)
            guard let anchor = certs.first(where: {
                guard let issuer = SecCertificateCopyNormalizedIssuerSequence($0) else {
                    return false
                }
                guard let subject = SecCertificateCopyNormalizedSubjectSequence($0) else {
                    return false
                }
                return issuer == subject
            }) else {
                XCTFail()
                return
            }
            var trust: SecTrust?
            certs.append(identity.certificate)
            guard SecTrustCreateWithCertificates(certs as CFTypeRef, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, trust != nil else {
                XCTFail()
                return
            }
            SecTrustSetAnchorCertificates(trust!, [anchor] as CFArray)
            var error: CFError?
            let trusted: Bool
            if #available(iOS 12.0, macOS 10.14, macCatalyst 13.0, tvOS 12.0, watchOS 5.0, *) {
                trusted = SecTrustEvaluateWithError(trust!, &error) && error == nil
            } else {
                var result: SecTrustResultType = .unspecified
                if SecTrustEvaluate(trust!, &result) == errSecSuccess, (result == .proceed || result == .unspecified) {
                    trusted = true
                } else {
                    trusted = false
                }
            }
            XCTAssertTrue(trusted)
        } catch {
            XCTFail()
        }
    }
    
    func testGetCertificateSerialNumber_returnsCorrectValue() throws {
        //d509c289-02fa-483c-bd6f-90e8c212e19c
        guard #available(iOS 10.3, macOS 10.13, watchOS 3.3, macCatalyst 13.0, tvOS 10.3, *) else {
            return
        }
        let url = try self.identityFileURL()
        let identity = try VerIDIdentity(url: url, password: self.correctPassword)
        XCTAssertNotNil(identity.certificate.serialNumber)
        XCTAssertEqual(identity.certificate.serialNumber!, 5)
    }
    
    private func identityFileURL() throws -> URL {
        guard let url = Bundle(for: type(of: self)).url(forResource: "Ver-ID identity", withExtension: "p12") else {
            throw IdentityError.missingIdentityFile
        }
        return url
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
