//
//  TestAppTests.swift
//  TestAppTests
//
//  Created by Jakub Dolejs on 11/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import XCTest
import Combine
import OHHTTPStubs
import OHHTTPStubsSwift
import ShieldX509
import ShieldSecurity
import ShieldPKCS
import PotentASN1
@testable import TestApp

final class TestAppTests: XCTestCase {
    
    var cancellables: [AnyCancellable] = []
    var testRunner: TestRunner!
    
    
    override func setUp() {
        self.testRunner = TestRunner()
        HTTPStubs.setEnabled(true)
        stub(condition: isHost("licensing.ver-id.com") && isMethodGET()) { request in
            if let url = request.url, url.path().hasSuffix("api/certificates/verid.client.identity") {
                do {
                    let renewedCert = try self.testRunner.createCertificate(expiryDays: 90)
                    guard let data = renewedCert.pemEncoded.data(using: .utf8) else {
                        throw "Failed to convert renewed certificate PEM string to data"
                    }
                    return HTTPStubsResponse(data: data, statusCode: 200, headers: [
                        "Content-Type": "application/x-pem-file",
                        "Content-Disposition": "attachment;filename=\"verid.client.identity.pem\""
                    ])
                } catch {
                    return HTTPStubsResponse(error: "Failed to load certificate")
                }
            }
            return HTTPStubsResponse(data: Data(), statusCode: 404, headers: nil)
        }
        stub(condition: isHost("licensing.ver-id.com") && isMethodPOST()) { request in
            if let url = request.url, url.path().hasSuffix("api/certificates/verid.client.identity") {
                do {
                    guard let csrBody = request.ohhttpStubs_httpBody, let csrPem = String(data: csrBody, encoding: .utf8) else {
                        throw "Request has no body"
                    }
                    let csrData = try self.csrFromPEM(csrPem)
                    let csr = try ASN1Decoder(schema: CertificationRequest.asn1Schema).decode(CertificationRequest.self, from: csrData)
                    guard let signingKey = self.testRunner.signingPrivateKey else {
                        throw "Failed to get signing key from test runner"
                    }
                    let cert = try Certificate.Builder(
                        issuer: NameBuilder().add("com.appliedrec.ver-id.standalone",  forTypeName: "CN").name,
                        subject: csr.certificationRequestInfo.subject,
                        subjectPublicKeyInfo: csr.certificationRequestInfo.subjectPKInfo,
                        notAfter: .init(date: Date().addingTimeInterval(365 * 24 * 60 * 60), timeZone: .gmt)).build(signingKey: signingKey, digestAlgorithm: .sha256)
                    let der = try cert.encoded()
                    let certPEM = """
-----BEGIN CERTIFICATE-----
\(der.base64EncodedString(options: .lineLength64Characters))
-----END CERTIFICATE-----
"""
                    guard let certData = certPEM.data(using: .utf8) else {
                        throw "Failed to encode PEM to data"
                    }
                    return HTTPStubsResponse(data: certData, statusCode: 200, headers: [
                        "Content-Type": "application/x-pem-file"
                    ])
                } catch {
                    return HTTPStubsResponse(error: "Failed to renew certificate")
                }
            }
            return HTTPStubsResponse(data: Data(), statusCode: 404, headers: nil)
        }
    }
    
    override func tearDown() {
        HTTPStubs.removeAllStubs()
        HTTPStubs.setEnabled(false)
    }

    func testRunAppTests() async throws {
        await self.testRunner.runTests()
        self.testRunner.testResults.filter { !$0.passed }.forEach {
            XCTFail("\($0.id) failed" + ($0.comments != nil ? ": \($0.comments!)" : ""))
        }
    }
    
    func testGetCertificateIssuer() throws {
        let cert = try self.testRunner.createCertificate(expiryDays: 90)
        let issuer = try cert.issuer
        XCTAssertEqual(issuer, .standalone)
    }
    
    private func csrFromPEM(_ pem: String) throws -> Data {
        let pattern = "-----BEGIN\\sCERTIFICATE\\sREQUEST-----((.|\\n)+?)-----END\\sCERTIFICATE\\sREQUEST-----"
        let range = NSRange(location: 0, length: pem.utf16.count)
        let regex = try! NSRegularExpression(pattern: pattern, options: .allowCommentsAndWhitespace)
        let matches = regex.matches(in: pem, options: [], range: range)
        if let csr: Data = matches.compactMap({ result in
            let base64 = pem[Range(result.range(at: 1), in: pem)!].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let keyData = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
                return nil
            }
            return keyData
        }).first {
            return csr
        }
        throw "Failed to create CSR"
    }
}
