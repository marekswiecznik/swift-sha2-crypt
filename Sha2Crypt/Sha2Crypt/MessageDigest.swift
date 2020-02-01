//
//  MessageDigest.swift
//  Sha2Crypt
//
//  Created by Marek on 01/02/2020.
//  Copyright © 2020 Minty Apps. All rights reserved.
//

import CommonCrypto

// CommonDigest wrapper interface
protocol MessageDigest {
    init(_ data: Data?)
    func update(_ data: Data)
    func digest() -> Data
}

class MessageDigest512: MessageDigest {
    private let hashLength = Int(CC_SHA512_DIGEST_LENGTH)
    private let context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
    
    required init(_ data: Data? = nil) {
        CC_SHA512_Init(context)
        if let data = data {
            update(data)
        }
    }
    
    func update(_ data: Data) {
        data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> Void in
            CC_SHA512_Update(context, bytes, CC_LONG(data.count))
        }
    }
    
    func digest() -> Data {
        var digest = Array<UInt8>(repeating: 0, count: self.hashLength)
        CC_SHA512_Final(&digest, context)
        return Data(digest)
    }
}

class MessageDigest256: MessageDigest {
    private let hashLength = Int(CC_SHA256_DIGEST_LENGTH)
    private let context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity: 1)
    
    required init(_ data: Data? = nil) {
        CC_SHA256_Init(context)
        if let data = data {
            update(data)
        }
    }
    
    func update(_ data: Data) {
        data.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) -> Void in
            CC_SHA256_Update(context, bytes, CC_LONG(data.count))
        }
    }
    
    func digest() -> Data {
        var digest = Array<UInt8>(repeating: 0, count: self.hashLength)
        CC_SHA256_Final(&digest, context)
        return Data(digest)
    }
}
