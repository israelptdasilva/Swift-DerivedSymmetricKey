import Foundation
import CryptoKit

// Alice create a private from wich a new public key and key agreement will be made.
let alicePrivateKey = P256.KeyAgreement.PrivateKey()

// Bob too prepares his private key to create a public key and a key agreement.
let bobPrivateKey = P256.KeyAgreement.PrivateKey()

// Alice derives a public key from her private one to share with Bob as part of a key agreement.
let alicePublicKey = alicePrivateKey.publicKey

// Bob too creates hist public key to share with Alice in the key agreement.
let bobPublicKey = bobPrivateKey.publicKey

// Alice agrees to use bob public key to use during their order exchange.
let aliceAgreement = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)

// Bob too agrees to use Alice's public key.
let bobAgreement = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)

// Now alice has a key that can encrypt data that Bob can decrypt and vice-versa.
let aliceSymetricKey = aliceAgreement.hkdfDerivedSymmetricKey(using: SHA256.self, salt: "".data(using: .utf8)!, sharedInfo: "".data(using: .utf8)!, outputByteCount: 32)

// Bob too has a key with which messages can be encrypted and decrypted by him and Alice.
let bobSymetricKey = bobAgreement.hkdfDerivedSymmetricKey(using: SHA256.self, salt: "".data(using: .utf8)!, sharedInfo: "".data(using: .utf8)!, outputByteCount: 32)

/// A struct that represents a money order that can be sent to different users.
struct Order: Encodable, Decodable {
    
    /// The money order unique identifier.
    let id: UUID
    /// The money order amount.
    let amount: Float
    /// The account to which the money will be transfered to.
    let account: Int
    
    // MARK: Decodable
    
    enum CodingKeys: String, CodingKey {
        case id
        case amount
        case account
    }
}

let order = Order(id: UUID(), amount: 10.50, account: 35442)

// Encode, hash and seal the order.
let encoded = try PropertyListEncoder().encode(order)

// Hash the encoded order so the receiver can verified that the order has the same hash value.
let hash = SHA256.hash(data: encoded)

// Encrypt the order using the American Encryption Standard (AES) algorithm.
let sealedBox = try AES.GCM.seal(encoded, using: aliceSymetricKey)

/// A struct that has a sealed order and its hashed value.
struct Transfer {
    
    /// The hash value of the sealed order.
    let hash: SHA256.Digest
    
    /// A sealed box with an order.
    let sealedBox: AES.GCM.SealedBox
}

let transfer = Transfer(hash: hash, sealedBox: sealedBox)

// Bob opens the box and decodes the order.
let remoteData = try AES.GCM.open(transfer.sealedBox, using: bobSymetricKey)
let remoteOrder: Order = try PropertyListDecoder().decode(Order.self, from: remoteData)
print(remoteOrder.amount)
print(remoteOrder.account)
