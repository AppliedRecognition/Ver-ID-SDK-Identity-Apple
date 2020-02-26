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
        XCTAssertThrowsError(try VerIDSDKIdentity(url: nil, password: nil))
    }
    
    func testCreateClient_succeeds() {
        do {
            let url = try self.identityFileURL()
            XCTAssertNoThrow(try VerIDSDKIdentity(url: url, password: self.correctPassword))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateClient_failMissingPassword() {
        do {
            let url = try self.identityFileURL()
            XCTAssertThrowsError(try VerIDSDKIdentity(url: url))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateClient_failMissingIdentityFile() {
        XCTAssertThrowsError(try VerIDSDKIdentity(password: self.correctPassword))
    }
    
    func testCreateClient_failInvalidPassword() {
        do {
            let url = try self.identityFileURL()
            XCTAssertThrowsError(try VerIDSDKIdentity(url: url, password: "nonsense"))
        } catch {
            XCTFail()
        }
    }
    
    func testCreateIdentityFromRemoteURL_succeeds() {
        guard let url = URL(string: "https://ver-id.s3.us-east-1.amazonaws.com/ios/com.appliedrec.verid.licenceclient/test_assets/Ver-ID%20identity.p12") else {
            XCTFail()
            return
        }
        XCTAssertNoThrow(try VerIDSDKIdentity(url: url, password: self.correctPassword))
    }
    
    func testClientCommonName_matches() {
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDSDKIdentity(url: url, password: self.correctPassword)
            XCTAssertEqual(self.commonName, identity.commonName)
        } catch {
            XCTFail()
        }
    }
    
    func testSignMessage_succeeds() {
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDSDKIdentity(url: url, password: self.correctPassword)
            let message = Data([UInt8](repeating: 0, count: 8))
            XCTAssertNoThrow(try identity.sign(message))
        } catch {
           XCTFail()
       }
    }
    
    func testVerifySignature_succeeds() {
        do {
            let url = try self.identityFileURL()
            let identity = try VerIDSDKIdentity(url: url, password: self.correctPassword)
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
    
    private func identityFileURL() throws -> URL {
        guard let url = Bundle(for: type(of: self)).url(forResource: "Ver-ID identity", withExtension: "p12") else {
            throw IdentityError.missingIdentityFile
        }
        return url
    }

}
