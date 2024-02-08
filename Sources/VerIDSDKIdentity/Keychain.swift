//
//  Keychain.swift
//  VerIDSDKIdentity
//
//  Created by Jakub Dolejs on 16/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import Foundation
import Security

class Keychain {
    
    let identifier: String
    
    init(identifier: String) {
        self.identifier = identifier
    }
    
    var privateKey: SecKey? {
        get {
            if let data = self["privateKey"] {
                let attributes: [CFString: Any] = [
                    kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass: kSecAttrKeyClassPrivate
                ]
                var error: Unmanaged<CFError>?
                guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
                    if let err = error?.takeRetainedValue() {
                        NSLog("⚠️ Failed to create key from data: %@", err.localizedDescription)
                    }
                    return nil
                }
                return key
            }
            return nil
        }
        set {
            if let key = newValue {
                var error: Unmanaged<CFError>?
                guard let data = SecKeyCopyExternalRepresentation(key, &error) else {
                    if let err = error?.takeRetainedValue() {
                        NSLog("⚠️ Failed to copy key to data: %@", err.localizedDescription)
                    }
                    return
                }
                self["privateKey"] = data as Data
            } else {
                self["privateKey"] = nil
            }
        }
    }
    
    var certificate: SecCertificate? {
        get {
            if let data = self["certificate"], let cert = SecCertificateCreateWithData(nil, data as CFData) {
                return cert
            }
            return nil
        }
        set {
            if let cert = newValue {
                if let existingCert = self.certificate, (existingCert.expiresAfter(cert) || !existingCert.hasSamePublicKey(as: cert)) {
                    return
                }
                let data = SecCertificateCopyData(cert)
                self["certificate"] = data as Data
            } else {
                self["certificate"] = nil
            }
        }
    }
    
    subscript(key: String) -> Data? {
        get {
            let query: [CFString: Any] = self.queryForKey(key, returnData: true)
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecSuccess, let data = result {
                return (data as! Data)
            }
            return nil
        }
        set {
            if let data = newValue {
                let query: [CFString: Any] = self.queryForKey(key, returnData: false)
                let update: [CFString: Any] = [kSecValueData: data]
                var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
                if status == errSecItemNotFound {
                    var insert = self.queryForKey(key, returnData: false)
                    insert[kSecValueData] = data
                    status = SecItemAdd(insert as CFDictionary, nil)
                }
                if status != errSecSuccess, let error = SecCopyErrorMessageString(status, nil) {
                    NSLog("⚠️ Failed to save %@ to keychain: %@", key, error as String)
                }
            } else {
                let query = self.queryForKey(key, returnData: false)
                let status = SecItemDelete(query as CFDictionary)
                if status != errSecSuccess && status != errSecItemNotFound, let error = SecCopyErrorMessageString(status, nil) {
                    NSLog("⚠️ Failed to delete %@ to keychain: %@", key, error as String)
                }
            }
        }
    }
    
    func clear() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: self.identifier
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess, let error = SecCopyErrorMessageString(status, nil) {
            NSLog("⚠️ Failed to clear keychain: %@", error as String)
        }
    }
    
    private func queryForKey(_ key: String, returnData: Bool) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: self.identifier,
            kSecAttrAccount: key
        ]
        if returnData {
            query[kSecReturnData] = kCFBooleanTrue!
        }
        return query
    }
}
