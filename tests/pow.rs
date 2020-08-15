/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use p0w::{Proofs, Tree};

// ======================================== #[test] pow() ======================================= \\

#[test]
fn pow() {
    //  8 =>  5158 bytes
    // 12 => 20158 bytes
    // 16 => 46118 bytes
    // 18 => 61518 bytes
    let tree = Tree::par_new("foobar", 8);
    let proofs = tree.gen_proofs();

    println!("{}", bincode::serialized_size(&proofs).unwrap());
}
