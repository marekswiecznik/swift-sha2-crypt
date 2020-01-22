
import Foundation
import CommonCrypto


enum MessageDigestError: Error {
    case wrongAlgorithm
}

class MessageDigest {
    private let hashLength = Int(CC_SHA512_DIGEST_LENGTH)
    private let context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity: 1)
    
    init(_ data: Data? = nil) throws {
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
    
    func finish() -> Data {
        var digest = Array<UInt8>(repeating:0, count: self.hashLength)
        CC_SHA512_Final(&digest, context)
        return Data(bytes: digest)
    }
    
    func digest() -> Data {
        return finish()
    }
    
    class func sha512(password: String, salt: String) throws -> String {
//        let dataPassword: Data = password.data(using: .utf8)!
//        let dataSalt: Data = salt.data(using: .utf8)!
        let hash = try _raw_sha2_crypt(pwdString: password, saltString: salt, rounds: 5000) // 656000
        return "$6$\(salt)$\(hash)"
    }
}

let _BNULL: UInt8 = 0

let _c_digest_offsets: [(UInt8, UInt8)] = [
    (0, 3), (5, 1), (5, 3), (1, 2), (5, 1), (5, 3), (1, 3),
    (4, 1), (5, 3), (1, 3), (5, 0), (5, 3), (1, 3), (5, 1),
    (4, 3), (1, 3), (5, 1), (5, 2), (1, 3), (5, 1), (5, 3),
]

// map used to transpose bytes when encoding final sha512_crypt digest
let _512_transpose_map = [
    42, 21,  0,  1, 43, 22, 23,  2, 44, 45, 24,  3,  4, 46, 25, 26,
    5, 47, 48, 27,  6,  7, 49, 28, 29,  8, 50, 51, 30,  9, 10, 52,
    31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
    16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
]


func _raw_sha2_crypt(pwdString: String, saltString: String, rounds: Int) throws -> String {
    /* perform raw sha256-crypt / sha512-crypt
     this function provides a pure-python implementation of the internals
     for the SHA256-Crypt and SHA512-Crypt algorithms; it doesn't
     handle any of the parsing/validation of the hash strings themselves.
     :arg pwd: password chars/bytes to hash
     :arg salt: salt chars to use
     :arg rounds: linear rounds cost
     :arg use_512: use sha512-crypt instead of sha256-crypt mode
     :returns:
     encoded checksum chars
     
     // ===================================================================
     //  init & validate inputs
     // ===================================================================
     
     //  NOTE: the setup portion of this algorithm scales ~linearly in time
     //        with the size of the password, making it vulnerable to a DOS from
     //        unreasonably large inputs. the following code has some optimizations
     //        which would make things even worse, using O(pwd_len**2) memory
     //        when calculating digest P.
     //
     //        to mitigate these two issues: 1) this code switches to a
     //        O(pwd_len)-memory algorithm for passwords that are much larger
     //        than average, and 2) Passlib enforces a library-wide max limit on
     //        the size of passwords it will allow, to prevent this algorithm and
     //        others from being DOSed in this way (see passlib.exc.PasswordSizeError
     //        for details).
     */
    
    let pwd: Data = pwdString.data(using: .utf8)!
    //if _BNULL in pwd:
    //raise uh.exc.NullPasswordError(sha512_crypt if use_512 else sha256_crypt)
    let pwd_len = pwd.count
    
    //  validate rounds
    assert(1000 <= rounds && rounds <= 999999999, "invalid rounds")
    //  NOTE: spec says out-of-range rounds should be clipped, instead of
    //  causing an error. this function assumes that's been taken care of
    //  by the handler class.
    
    //  validate salt
    let salt: Data = saltString.data(using: .ascii)!
    let salt_len = salt.count
    assert(salt_len < 17, "salt too large")
    //  NOTE: spec says salts larger than 16 bytes should be truncated,
    //  instead of causing an error. this function assumes that's been
    //  taken care of by the handler class.
    
    //  load sha256/512 specific constants
    let hash_const = MessageDigest.init
    let transpose_map = _512_transpose_map
    
    // ===================================================================
    //  digest B - used as subinput to digest A
    // ===================================================================
    let db = try hash_const(pwd + salt + pwd).digest()
    
    // ===================================================================
    //  digest A - used to initialize first round of digest C
    // ===================================================================
    //  start out with pwd + salt
    let a_ctx = try hash_const(pwd + salt)
    
    //  add pwd_len bytes of b, repeating b as many times as needed.
    a_ctx.update(repeat_string(db, pwd_len))
    
    //  for each bit in pwd_len: add b if it's 1, or pwd if it's 0
    var i = pwd_len
    while i > 0 {
        a_ctx.update(i & 1 != 0 ? db : pwd)
        i >>= 1
    }
    
    //  finish A
    let da = a_ctx.digest()
    
    // ===================================================================
    //  digest P from password - used instead of password itself
    //                           when calculating digest C.
    // ===================================================================
    let dp: Data
    if pwd_len < 96 {
        //  this method is faster under python, but uses O(pwd_len**2) memory;
        //  so we don't use it for larger passwords to avoid a potential DOS.
        dp = repeat_string(try hash_const(pwd * pwd_len).digest(), pwd_len)
    } else {
        //  this method is slower under python, but uses a fixed amount of memory.
        let tmp_ctx = try hash_const(pwd)
        i = pwd_len-1
        while i > 0 {
            tmp_ctx.update(pwd)
            i -= 1
        }
        dp = repeat_string(tmp_ctx.digest(), pwd_len)
    }
    assert(dp.count == pwd_len)
    
    // ===================================================================
    //  digest S  - used instead of salt itself when calculating digest C
    // ===================================================================
    let ds = try hash_const(salt * (16 + Int(da[0]))).digest()[0..<salt_len]
    assert(ds.count == salt_len, "salt_len somehow > hash_len!")
    
    // ===================================================================
    //  digest C - for a variable number of rounds, combine A, S, and P
    //             digests in various ways; in order to burn CPU time.
    // ===================================================================
    
    //  NOTE: the original SHA256/512-Crypt specification performs the C digest
    //  calculation using the following loop:
    //
    // #dc = da
    // #i = 0
    // #while i < rounds:
    // #    tmp_ctx = hash_const(dp if i & 1 else dc)
    // #    if i % 3:
    // #        tmp_ctx.update(ds)
    // #    if i % 7:
    // #        tmp_ctx.update(dp)
    // #    tmp_ctx.update(dc if i & 1 else dp)
    // #    dc = tmp_ctx.digest()
    // #    i += 1
    //
    //  The code Passlib uses (below) implements an equivalent algorithm,
    //  it's just been heavily optimized to pre-calculate a large number
    //  of things beforehand. It works off of a couple of observations
    //  about the original algorithm:
    //
    //  1. each round is a combination of 'dc', 'ds', and 'dp'; determined
    //     by the whether 'i' a multiple of 2,3, and/or 7.
    //  2. since lcm(2,3,7)==42, the series of combinations will repeat
    //     every 42 rounds.
    //  3. even rounds 0-40 consist of 'hash(dc + round-specific-constant)';
    //     while odd rounds 1-41 consist of hash(round-specific-constant + dc)
    //
    //  Using these observations, the following code...
    //  * calculates the round-specific combination of ds & dp for each round 0-41
    //  * runs through as many 42-round blocks as possible
    //  * runs through as many pairs of rounds as possible for remaining rounds
    //  * performs once last round if the total rounds should be odd.
    //
    //  this cuts out a lot of the control overhead incurred when running the
    //  original loop 40,000+ times in python, resulting in ~20% increase in
    //  speed under CPython (though still 2x slower than glibc crypt)
    
    //  prepare the 6 combinations of ds & dp which are needed
    //  (order of 'perms' must match how _c_digest_offsets was generated)
    let dp_dp = dp+dp
    let dp_ds = dp+ds
    let perms = [dp, dp_dp, dp_ds, dp_ds+dp, ds+dp, ds+dp_dp]
    
    //  build up list of even-round & odd-round constants,
    //  and store in 21-element list as (even,odd) pairs.
//    let data = [ (perms[even], perms[odd]) for even, odd in _c_digest_offsets]
    let data = _c_digest_offsets.map { (perms[Int($0.0)], perms[Int($0.1)]) }
    
    //  perform as many full 42-round blocks as possible
    var dc = da
    var (blocks, tail) = rounds.divMod(42)
    while blocks > 0 {
        for (even, odd) in data {
            dc = try hash_const(odd + hash_const(dc + even).digest()).digest()
            blocks -= 1
        }
    }
        
    // perform any leftover rounds
    if tail != 0 {
        //  perform any pairs of rounds
        let pairs = tail>>1
        for (even, odd) in data[0..<pairs] {
            dc = try hash_const(odd + hash_const(dc + even).digest()).digest()
            
            // if rounds was odd, do one last round (since we started at 0,
            // last round will be an even-numbered round)
            if tail & 1 != 0 {
                dc = try hash_const(dc + data[pairs].0).digest()
            }
        }
    }
    
    // ===================================================================
    //  encode digest using appropriate transpose map
    // ===================================================================
    return h64.encode_transposed_bytes(dc, transpose_map)//.decode("ascii")
}

func repeat_string(_ source: Data, _ size: Int) -> Data {
    // repeat or truncate <source> string, so it has length <size>
    let cur = source.count
    var target = Data(count: size)
    for i in 0..<size {
        target[i] = source[i % cur]
    }
    return target
}

let HASH64_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

let h64 = Base64Engine(HASH64_CHARS)

class Base64Engine {
    private let bytemap: String
    
    init(_ charmap: String, big: Bool = false) {
        self.bytemap = charmap
//        self._encode64 = charmap.__getitem__
//        lookup = dict((value, idx) for idx, value in enumerate(charmap))
//        self._decode64 = lookup.__getitem__
    }
    
    
    func _encode_bytes_little(_ next_value: inout IndexingIterator<[UInt8]>, _ chunks: Int, _ tail: Int) -> [UInt8] {
        var idx = 0
        var data = [UInt8]()
        while idx < chunks {
            let v1 = next_value.next()!
            let v2 = next_value.next()!
            let v3 = next_value.next()!
            data.append(v1 & 0x3f)
            data.append( ((v2 & 0x0f)<<2)|(v1>>6) )
            data.append( ((v3 & 0x03)<<4)|(v2>>4) )
            data.append( v3>>2 )
            idx += 1
        }
        if tail != 0 {
            let v1 = next_value.next()!
            if tail == 1 {
                data.append( v1 & 0x3f )
                data.append( v1>>6 )
            } else {
                assert( tail == 2)
                // note: 2 msb of last byte are padding
                let v2 = next_value.next()!
                data.append( v1 & 0x3f )
                data.append( ((v2 & 0x0f)<<2)|(v1>>6) )
                data.append( v2>>4 )
            }
        }
        return data
    }
    
    func encode_bytes(_ source: [UInt8]) -> String {
        let (chunks, tail) = source.count.divMod(3)
        var next_value = source.makeIterator()
        let gen = self._encode_bytes_little(&next_value, chunks, tail)
//        let out = join_byte_elems(imap(self._encode64, gen))
        let chars = self.bytemap.cString(using: .ascii)!
        let out = gen.map { chars[Int($0)] }
        return String(cString: out)
    }

    func encode_transposed_bytes(_ source: Data, _ offsets: [Int]) -> String {
//        let tmp = join_byte_elems(source[off] for off in offsets)
        let tmp = offsets.map { source[$0] }
        return self.encode_bytes(tmp)
    }
}

func * (left: Data, right: Int) -> Data {
    return (0..<right).reduce(Data(), { (acc, _) -> Data in
        acc + left
    })
}

extension Int {
    func divMod(_ other:Int) -> (quotient:Int, modulus:Int) {
        let quotient = self / other
        let remainder = self % other
        
        if (quotient > 0) || (remainder == 0) {
            return (quotient, remainder)
        } else if quotient == 0  && (self > 0) && (other < 0) {
            let div = quotient - 1
            let result = (div * other) - self
            return (div, -result)
        } else {
            let signSituation = ((self > 0) || (other < 0))
            let div = ((quotient == 0) && signSituation) ? quotient : quotient - 1
            let result = abs((div * other) - self)
            return (div, (other < 0) ? -result : result)
        }
    }
    
    internal func quotRem(other:Int) -> (quotient:Int, remainder:Int) {
        return (self / other, self % other)
    }
}

