package merklego

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

var (
	ErrNilBlock             = errors.New("Block to insert cannot be nil")
	ErrEmptyMerkleTree      = errors.New("Merkle tree cannot be empty; insert some blocks")
	ErrTreeAlreadyFinalized = errors.New("Merkle tree already finalized")
	ErrTreeNotFinalized     = errors.New("Merkle tree not finalized")
)

var (
	internalNodePrefix = '\x01'
	leafNodePrefix     = '\x00'
)

type (
	FlatMerkleTree struct {
		blocks    []Block
		nodes     []TreeNode
		root      TreeNode
		finalized bool
	}

	TreeNode []byte
	Block    []byte
)

func (t TreeNode) Bytes() []byte {
	return t
}

func (b Block) Bytes() []byte {
	return b
}

func NewMerkleTree(blocks ...Block) *FlatMerkleTree {
	return &FlatMerkleTree{
		blocks:    blocks,
		finalized: false,
	}
}

func (mt *FlatMerkleTree) String() (s string) {
	if rh, err := mt.RootHash(); err == nil {
		s = fmt.Sprintf("0x%s", hex.EncodeToString(rh))
	}

	return
}

func (mt *FlatMerkleTree) RootHash() ([]byte, error) {
	if !mt.finalized {
		return nil, fmt.Errorf("invalid root hash: %v", ErrTreeNotFinalized)
	}

	return copyNode(mt.root).Bytes(), nil
}

func (mt *FlatMerkleTree) Insert(block Block) error {
	if block == nil {
		return ErrNilBlock
	}

	if mt.finalized {
		return ErrTreeAlreadyFinalized
	}

	if mt.blocks == nil {
		mt.blocks = []Block{}
	}

	mt.blocks = append(mt.blocks, block)
	return nil
}

func (mt *FlatMerkleTree) Proof(block Block) ([]TreeNode, error) {
	if block == nil {
		return nil, ErrNilBlock
	}

	if !mt.finalized {
		return nil, ErrTreeNotFinalized
	}

	idx, err := mt.findLeaf(block)
	if err != nil {
		return nil, err
	}

	nodeIdx := idx
	k := 0
	proof := make([]TreeNode, int(math.Log2(float64(len(mt.nodes)))))

	for nodeIdx > 0 {
		if nodeIdx%2 == 0 {
			proof[k] = copyNode(mt.nodes[nodeIdx-1])
		} else {
			proof[k] = copyNode(mt.nodes[nodeIdx+1])
		}
		k++

		nodeIdx = (nodeIdx - 1) / 2
	}

	// Proof was requested for a block on the second to last level
	// So remove the empty last proof chunk
	if proof[len(proof)-1] == nil {
		return proof[:len(proof)-1], nil
	}

	return proof, nil
}

func (mt *FlatMerkleTree) Verify(block Block, proof []TreeNode) error {
	if !mt.finalized {
		return ErrTreeNotFinalized
	}

	leafIdx, err := mt.findLeaf(block)
	if err != nil {
		return err
	}

	currNodeIdx := leafIdx
	for i, proofChunk := range proof {
		var reconstructedNode TreeNode

		proofNodeBytes := copyNode(proofChunk)
		currentNodeBytes := copyNode(mt.nodes[currNodeIdx])

		// Append sibling to the left
		if currNodeIdx%2 == 0 {
			reconstructedNode = hashNode(append(proofNodeBytes, currentNodeBytes...), true)
		} else {
			reconstructedNode = hashNode(append(currentNodeBytes, proofNodeBytes...), true)
		}

		parentIdx := (currNodeIdx - 1) / 2
		parentNode := mt.nodes[parentIdx]

		if !bytes.Equal(parentNode.Bytes(), reconstructedNode.Bytes()) {
			return fmt.Errorf("invalid proof at index %d for block %X; got: %X, want: %X",
				i, block, reconstructedNode.Bytes(), parentNode.Bytes())
		}

		currNodeIdx = parentIdx
	}

	return nil
}

func (mt *FlatMerkleTree) Finalize() error {
	if len(mt.blocks) == 0 {
		return fmt.Errorf("Failed to finalize: %s", ErrEmptyMerkleTree)
	}

	if mt.finalized {
		return ErrTreeAlreadyFinalized
	}

	if len(mt.blocks)%2 != 0 {
		mt.blocks = append(mt.blocks, mt.blocks[len(mt.blocks)-1])
	}

	// A full binary tree composed from N items has 2 * N - 1 nodes.
	mt.nodes = make([]TreeNode, 2*len(mt.blocks)-1)

	// Set the leaf nodes to be in the last N array slots.
	// The merkle tree array will then have the first 2 * N - (N + 1) slots
	// with intermediate nodes, with 0 being the root.
	j := len(mt.nodes) - len(mt.blocks)
	for _, b := range mt.blocks {
		mt.nodes[j] = hashNode(b, false)
		j++
	}

	mt.root = mt.finalize(0)
	mt.finalized = true

	return nil
}

func (mt *FlatMerkleTree) finalize(idx int) TreeNode {
	if !mt.hasChild(idx) {
		return mt.nodes[idx]
	}

	left := mt.finalize(2*idx + 1)
	right := mt.finalize(2*idx + 2)

	mt.nodes[idx] = hashNode(append(left, right...), true)

	return mt.nodes[idx]
}

func (mt *FlatMerkleTree) findLeaf(block Block) (int, error) {
	if block == nil {
		return -1, ErrNilBlock
	}

	for i := 0; i < len(mt.blocks); i++ {
		if bytes.Equal(mt.blocks[i].Bytes(), block.Bytes()) {
			return len(mt.nodes) - len(mt.blocks) + i, nil
		}
	}

	return -1, fmt.Errorf("block does not exist: %v", hex.EncodeToString(block))
}

func (mt *FlatMerkleTree) hasChild(idx int) bool {
	n := len(mt.nodes)
	l := 2*idx + 1
	r := 2*idx + 2

	return l < n || r < n
}

func hashNode(data []byte, internal bool) TreeNode {
	raw := make(TreeNode, len(data)+1)

	if internal {
		raw[0] = byte(internalNodePrefix)
	}

	copy(raw[1:], data)
	sum := sha256.Sum256(raw)

	return TreeNode(sum[:])
}

func copyNode(node TreeNode) TreeNode {
	cpy := make(TreeNode, len(node))
	copy(cpy, node)
	return cpy
}
