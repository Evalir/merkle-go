package merklego

import (
	"crypto/sha256"
	"errors"
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
	Left   *Node
	Right  *Node
	Parent *Node
	leaf   bool
	dup    bool
	Hash   []byte
	Item   Storable
}

//MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

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
			leaf: true,
			dup:  false,
		})
	}

	if len(leaves)%2 == 1 {
		duplicate := &Node{
			leaf: true,
			dup:  true,
			Hash: leaves[len(leaves)-1].Hash,
			Item: leaves[len(leaves)-1].Item,
		}
		leaves = append(leaves, duplicate)
	}

	root, err := buildIntermediate(leaves, t)
	if err != nil {
		return nil, nil, err
	}

	return root, leaves, nil
}

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
			Left:  leaves[left],
			Right: leaves[right],
			Hash:  h.Sum(nil),
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
