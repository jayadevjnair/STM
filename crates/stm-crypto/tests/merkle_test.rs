use stm_crypto::{
    build_merkle_root,
    compute_leaf,
    empty_root,
};

#[test]
fn empty_tree_has_correct_root() {
    let root = build_merkle_root(vec![]);

    assert_eq!(root, empty_root());
}

#[test]
fn one_leaf_root_is_the_leaf() {
    let leaf = compute_leaf(b"hello");

    let root = build_merkle_root(vec![leaf]);

    assert_eq!(root, leaf);
}

#[test]
fn two_leaves_create_root() {
    let leaf1 = compute_leaf(b"object one");
    let leaf2 = compute_leaf(b"object two");

    let root = build_merkle_root(vec![leaf1, leaf2]);

    assert_ne!(root, leaf1);
    assert_ne!(root, leaf2);
}

#[test]
fn three_leaves_use_duplicate_last_rule() {
    let leaf1 = compute_leaf(b"one");
    let leaf2 = compute_leaf(b"two");
    let leaf3 = compute_leaf(b"three");

    let root1 = build_merkle_root(vec![leaf1, leaf2, leaf3]);
    let root2 = build_merkle_root(vec![leaf1, leaf2, leaf3]);

    assert_eq!(root1, root2);
}