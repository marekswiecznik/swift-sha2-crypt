//
//  Sha2CryptTests.swift
//  Sha2CryptTests
//
//  Created by Marek on 01/02/2020.
//  Copyright © 2020 Minty Apps. All rights reserved.
//

import XCTest
@testable import Sha2Crypt

class SHA2CryptTests: XCTestCase {
    let expected: [(String, String, String)] = [
        ("123456", "SomeSalt", "$6$SomeSalt$pYs2RqI5HAFSVGMxB0kYEJhW.EUPnQnodWGXUEX4bMHUebq5/L7I/d1jpfTZMarhR8ughk7XCHjITyBG4bj3M/"),
        ("@#$@#LFDS)I@#(HEFDSłóźżń", "123456", "$6$123456$J7Tjxj.OYfFoWqTlpAG.mqUmay0jgjHDppojZYZ2Pac.0d3IzDv8B3WoSc2eJYQchx3xV8ZTKaSFWapjJz2.P."),
        ("SimplePassword", "TJGEDFSHVasd123", "$6$TJGEDFSHVasd123$lCFvTOp0y84tP5438c2rIhCsinaHsdpFDgPKBtsOMeLU350o831UJnj64rSvVa9Urw0liS7LYur6X5gazyFqA.")
    ]

    func testSha512Crypt() throws {
        for (pass, salt, expected) in self.expected {
            let actual = sha512Crypt(password: pass, salt: salt)
            XCTAssertEqual(expected, actual)
        }
    }
}
