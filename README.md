# Swift SHA2 Crypt

## Welcome

This is a Swift port of a pure-python implementation of the internals for the SHA256-Crypt and SHA512-Crypt algorithms; it doesn't handle any of the parsing/validation of the hash strings themselves.

## Usage

    let hash512 = sha512Crypt(password: "pass", salt: "salt")
    // outputs: $6$salt$3aEJgflnzWuw1O3tr0IYSmhUY0cZ7iBQeBP392T7RXjLP3TKKu3ddIapQaCpbD4p9ioeGaVIjOHaym7HvCuUm0

    let hash256 = sha256Crypt(password: "pass", salt: "salt")
    // outputs: $5$salt$BVuUtQaoLQNxrhdvvoTwUW5F0BihI9JdpEEgVrKrp6C

## Credits

Original implementation of the SHA2_crypt handler form Passlib python library:  https://github.com/efficks/passlib/blob/master/passlib/handlers/sha2_crypt.py.

Passlib is (c) Assurance Technologies, and is released under the BSD license: https://github.com/efficks/passlib/blob/master/LICENSE

