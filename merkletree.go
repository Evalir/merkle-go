package merklego

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

// Storable represents an item in the merkle tree.
type Storable interface {
	CalculateHash() ([]byte, error)
	Equals(other Storable) (bool, error)
}

type MerkleTree struct {
	Root       *Node
	merkleRoot []byte
	Leaves     []*Node
	hashFunc   func() hash.Hash
}

type Node struct {
	Hash   []byte
	Item   Storable
	Left   *Node
	Parent *Node
	Right  *Node
	Tree   *MerkleTree
	dup    bool
	leaf   bool
}

//MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

func (n *Node) VerifyNode() ([]byte, error) {
	if n.leaf {
		return n.Item.CalculateHash()
	}

	leftBytes, err := n.Left.VerifyNode()
	if err != nil {
		return nil, err
	}

	rightBytes, err := n.Right.VerifyNode()
	if err != nil {
		return nil, err
	}

	hf := n.Tree.hashFunc()
	if _, err := hf.Write(append(leftBytes, rightBytes...)); err != nil {
		return nil, err
	}

	return hf.Sum(nil), nil
}

// NewTree creates a new merkle tree with the Storable contents in content.
func NewTree(content []Storable) (*MerkleTree, error) {
	var defaultHashFunc = sha256.New

	t := &MerkleTree{
		hashFunc: defaultHashFunc,
	}

	if len(content) == 0 {
		return nil, errors.New("error: cannot make a merkle tree without any contents.")
	}

	root, leafs, err := buildTree(content, t)
	if err != nil {
		return nil, err
	}

	t.Root = root
	t.Leaves = leafs
	t.merkleRoot = root.Hash

	return t, nil
}

// buildTree builds a new Merkle Tree with the contents from content.
// It first builds the leaf nodes,
// and then starts building the subsequent parents until it reaches the root.
func buildTree(content []Storable, t *MerkleTree) (*Node, []*Node, error) {
	var leaves []*Node

	for _, c := range content {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leaves = append(leaves, &Node{
			Hash: hash,
			Item: c,
			Tree: t,
			dup:  false,
			leaf: true,
		})
	}

	if len(leaves)%2 == 1 {
		duplicate := &Node{
			Hash: leaves[len(leaves)-1].Hash,
			Item: leaves[len(leaves)-1].Item,
			Tree: t,
			dup:  true,
			leaf: true,
		}
		leaves = append(leaves, duplicate)
	}

	root, err := buildIntermediate(leaves, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leaves, nil
}

// buildIntermediate builds the intermediate part of the tree, above the leaves,
// until it reaches the root.
func buildIntermediate(leaves []*Node, t *MerkleTree) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(leaves); i += 2 {
		h := t.hashFunc()
		var left, right int = i, i + 1

		// Avoid accessing an out-of-bounds position
		// Also handles the cases where len(leaves) % 2 != 1
		if i+1 == len(leaves) {
			right = i
		}

		itemHash := append(leaves[left].Hash, leaves[right].Hash...)
		if _, err := h.Write(itemHash); err != nil {
			return nil, err
		}

		n := &Node{
			Hash:  h.Sum(nil),
			Left:  leaves[left],
			Right: leaves[right],
			Tree:  t,
		}

		nodes = append(nodes, n)

		leaves[left].Parent = n
		leaves[right].Parent = n

		if len(leaves) == 2 {
			return n, nil
		}
	}

	return buildIntermediate(nodes, t)
}

//String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", n.leaf, n.dup, n.Hash, n.Item)
}
