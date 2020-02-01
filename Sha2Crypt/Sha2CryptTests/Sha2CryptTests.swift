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
    // FIXME change data without salt
    let expected: [(String, String, String)] = [
        ("#?>C?<SDJR@#$I)EWJSDFOSAą", "123456", "$6$123456$7zVptl5ZShqAa98votK1RWoe9vxsylMpYY65/TX6fuWFK8L01GTNOnn2ojvmNWQ32K4Z./MSug1Y1HV0mge9V/"),
        ("FHome", "123456", "$6$123456$QNg.uIOwxOhnOsTnpEyAGeHfKNMkHQcm.wKdxfglXtwHoj5NMNb8HKwBn4Wjvhvl3JHNdj0edjyAc/0uNUCOm0"),
        ("123456", "FHome", "$6$FHome$ZCLzvRGQTKjiZr1PPtmvaIUKpy7Ulp2C6oeWQMYnt1/QzETIEjXaLe9S0/JL50sttYZHemM7z/TffOak3CgpA/")
    ]

    func testSha512Crypt() throws {
        for (pass, salt, expected) in self.expected {
            let actual = try sha512Crypt(password: pass, salt: salt)
            XCTAssertEqual(expected, actual)
        }
    }
}
