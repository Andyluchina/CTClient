package zklib

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// setBigIntWithBytes sets a big.Int value using a slice of bytes and returns the big.Int.
func SetBigIntWithBytes(b []byte) *big.Int {
	var num big.Int
	num.SetBytes(b) // Interpret b as a big-endian unsigned integer
	return &num
}

func IntToBigInt(n []int) []*big.Int {
	bigInts := make([]*big.Int, len(n))
	for i, val := range n {
		bigInts[i] = big.NewInt(int64(val))
	}
	return bigInts
}

// generatePermutationMatrix generates a permutation matrix of size n using cryptographically secure randomness.
func GeneratePermutationMatrix(n int) [][]int {
	// Initialize the matrix with zeros.
	matrix := make([][]int, n)
	for i := range matrix {
		matrix[i] = make([]int, n)
	}

	// Generate a cryptographically secure permutation of 0 to n-1.
	perm := securePerm(n)

	// Fill the matrix with 1s according to the permutation.
	for i, val := range perm {
		matrix[i][val] = 1
	}

	return matrix
}

// securePerm generates a cryptographically secure permutation of n integers.
func securePerm(n int) []int {
	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}

	for i := 1; i < n; i++ {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		perm[i], perm[j.Int64()] = perm[j.Int64()], perm[i]
	}

	return perm
}

// printMatrix prints the matrix.
func PrintMatrix(matrix [][]int) {
	for _, row := range matrix {
		for _, val := range row {
			fmt.Printf("%d ", val)
		}
		fmt.Println()
	}
}

// inversePermutationMatrix computes the inverse of a permutation matrix.
func InversePermutationMatrix(matrix [][]int) ([][]int, error) {
	n := len(matrix)
	// Initialize the inverse matrix with zeros
	inverseMatrix := make([][]int, n)
	for i := 0; i < n; i++ {
		inverseMatrix[i] = make([]int, n)
	}

	// Fill in the inverse matrix
	for rowIndex, row := range matrix {
		found := false
		for colIndex, val := range row {
			if val == 1 {
				if found { // Ensure there's only one '1' per row
					return nil, fmt.Errorf("invalid permutation matrix: multiple 1s in row")
				}
				if inverseMatrix[colIndex][rowIndex] == 1 {
					return nil, fmt.Errorf("invalid permutation matrix: multiple 1s in column")
				}
				inverseMatrix[colIndex][rowIndex] = 1
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid permutation matrix: no 1 found in row")
		}
	}

	return inverseMatrix, nil
}

func ForwardMapping(index int, matrix [][]int) (int, error) {
	row := matrix[index]
	for i, val := range row {
		if val == 1 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no 1 found in row")
}

func BackwardMapping(index int, matrix [][]int) (int, error) {
	invm, _ := InversePermutationMatrix(matrix)
	row := invm[index]
	for i, val := range row {
		if val == 1 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("no 1 found in row")
}

func isGenerator(g *big.Int, p *big.Int, q *big.Int) bool {
	group_order := new(big.Int).Mul(p, q)
	if !isCoprime(g, group_order) {
		return false
	}
	if new(big.Int).Exp(g, q, group_order).Cmp(big.NewInt(1)) != 0 && new(big.Int).Exp(g, p, group_order).Cmp(big.NewInt(1)) != 0 {
		return true
	}
	return false
}

// randomBigInt samples a random big.Int in the interval [a, b].
func randomBigInt(a, b *big.Int) (*big.Int, error) {
	// Ensure a <= b
	if a.Cmp(b) > 0 {
		return nil, fmt.Errorf("invalid interval: a must be less than or equal to b")
	}

	// Calculate the difference d = b - a
	d := new(big.Int).Sub(b, a)

	// Generate a random big.Int, r, in the interval [0, d]
	r, err := rand.Int(rand.Reader, new(big.Int).Add(d, big.NewInt(1))) // rand.Int samples in [0, n), so we add 1 to include b
	if err != nil {
		return nil, err
	}

	// Shift r to the interval [a, b] by adding a, resulting in a + r
	return r.Add(r, a), nil
}

func sampleAGenerator(p *big.Int, q *big.Int) *big.Int {
	for {
		g, err := randomBigInt(big.NewInt(2), new(big.Int).Mul(p, q))
		if err != nil {
			return nil
		}
		if isGenerator(g, p, q) {
			return g
		}
	}
}

func SampleNGenerators(p *big.Int, q *big.Int, g_needed int) []*big.Int {
	generators := make([]*big.Int, 0) // Fix: Change the type of generator to []*big.Int
	for i := 0; i < g_needed; i++ {
		generator := sampleAGenerator(p, q)
		generators = append(generators, generator) // Fix: Change the append statement to append a pointer to the generator slice
	}
	return generators // Fix: Change the return statement to return generator instead of &generator
}

func Generate_commitment(gs []*big.Int, ms []*big.Int, d_needed *big.Int, r []byte, N *big.Int) *big.Int {
	r_int := SetBigIntWithBytes(r)
	commitment := big.NewInt(1)
	for j := 0; j < len(ms); j++ {
		m := ms[j]
		commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[j], m, N)) // Fix: Add m as the second argument to Mul
	}
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)], d_needed, N))
	commitment = new(big.Int).Mul(commitment, new(big.Int).Exp(gs[len(ms)+1], r_int, N))
	commitment = new(big.Int).Mod(commitment, N)
	return commitment // Fix: Add return statement
}

// isCoprime uses the Euclidean algorithm to check if a and b are coprime.
func isCoprime(a, b *big.Int) bool {
	return new(big.Int).GCD(nil, nil, a, b).Cmp(big.NewInt(1)) == 0
}

// GenerateSecureRandomBits generates a slice of bytes of the specified bit length.
// Note: The bit length n must be divisible by 8, as it returns a slice of bytes.
func GenerateSecureRandomBits(n int) ([]byte, error) {
	if n%8 != 0 {
		return nil, fmt.Errorf("bit length must be divisible by 8")
	}
	numOfBytes := n / 8
	b := make([]byte, numOfBytes)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
