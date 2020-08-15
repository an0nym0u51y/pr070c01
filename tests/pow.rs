/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use p0w::Tree;

// ========================================= pow_size() ========================================= \\

fn pow_size(levels: usize) -> usize {
    let tree = Tree::par_new("foobar", levels);
    let proofs = tree.gen_proofs();

    bincode::serialized_size(&proofs).unwrap() as usize
}

// ===================================== #[test] pow_sizes() ==================================== \\

#[test]
fn pow_sizes() {
    //  8 =>  5158 bytes
    assert_eq!(pow_size(8), 5158);
    // 12 => 20158 bytes
    assert_eq!(pow_size(12), 20158);
    // 16 => 46118 bytes
    assert_eq!(pow_size(16), 46118);
    // 18 => 61518 bytes
    assert_eq!(pow_size(18), 61518);
}
