//
//  SecKeyExtension.swift
//  VerIDSDKIdentity
//
//  Created by Jakub Dolejs on 22/01/2024.
//  Copyright © 2024 Applied Recognition. All rights reserved.
//

import Foundation
import Security

public extension SecKey {
    
    var publicKey: SecKey? {
        return SecKeyCopyPublicKey(self)
    }
}
