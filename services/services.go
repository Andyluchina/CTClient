package services

import (
	"CTLogchecker/ClientApp/aes"
	"CTLogchecker/ClientApp/datastruct"
	"CTLogchecker/ClientApp/elgamal"
	"CTLogchecker/ClientApp/zklib"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"filippo.io/nistec"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type Client struct {
	ID              int
	ReportingKey    *ecdh.PrivateKey
	ShuffleKey      *ecdh.PrivateKey
	ReportingValue  []byte
	Curve           ecdh.Curve
	G_report        []byte /// init point needs to be different for every client
	H_report        []byte
	G_shuffle       []byte /// init point needs to be different for every client
	H_shuffle       []byte
	DH_Pub_H        []byte /// pub key for secrete sharing
	DH_Pub_private  []byte
	InitialG_ri0    []byte
	TotalClients    uint32
	RevealThreshold uint32
	Shamir_curve    *curves.Curve
	MyIP            string
	ShuffleTime     float64
	ShuffleUpload   int
	ShuffleDownload int
}

// NewAuditor creates a new Auditor instance
func NewClient(curve ecdh.Curve) *Client {
	k_report, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	k_shuffle, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dh_pub, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	g_report := elgamal.Generate_Random_Dice_point(curve)
	h_report, err := elgamal.ECDH_bytes(g_report, k_report.Bytes())
	if err != nil {
		panic(err)
	}

	g_shuffle := elgamal.Generate_Random_Dice_point(curve)
	h_shuffle, err := elgamal.ECDH_bytes(g_shuffle, k_shuffle.Bytes())
	if err != nil {
		panic(err)
	}

	dh_pub_h := dh_pub.PublicKey().Bytes()
	dh_pub_pri := dh_pub.Bytes()

	return &Client{
		ReportingKey:   k_report,
		ShuffleKey:     k_shuffle,
		ReportingValue: elgamal.Generate_certificate(),
		Curve:          curve,
		G_report:       g_report,
		H_report:       h_report,
		G_shuffle:      g_shuffle,
		H_shuffle:      h_shuffle,
		DH_Pub_H:       dh_pub_h,
		DH_Pub_private: dh_pub_pri,
	}
}

func CreateInitialEntry(client *Client) (*datastruct.ReportingEntry, error) {
	// segment the certficate with chaining
	segments, err := segmentBitsWithPadding_MapOnCurve(client.ReportingValue)
	if err != nil {
		fmt.Println("Error segmenting bits:", err)
		return nil, err
	}

	ri0 := elgamal.Generate_Random_Dice_seed(client.Curve)
	h_r_i0, err := elgamal.ECDH_bytes(client.H_report, ri0)
	if err != nil {
		return nil, err
	}
	/// generate the first two item
	cert_times_h_r10, err := EncryptSegments(h_r_i0, segments)
	if err != nil {
		return nil, err
	}
	// FIXED each client should have different g
	// generate g and report g with the randomizer
	g_r_i0, err := elgamal.ECDH_bytes(client.G_report, ri0)
	if err != nil {
		return nil, err
	}
	client.InitialG_ri0 = g_r_i0
	/// generate the second two item
	ri1 := elgamal.Generate_Random_Dice_seed(client.Curve)
	// if err != nil {
	// 	return nil, err
	// }
	h_r_i1, err := elgamal.ECDH_bytes(client.H_report, ri1)
	if err != nil {
		return nil, err
	}
	g_r_i1, err := elgamal.ECDH_bytes(client.G_report, ri1)
	if err != nil {
		return nil, err
	}

	return &datastruct.ReportingEntry{
		Cert_times_h_r10: cert_times_h_r10,
		// G_ri0:            g_r_i0,
		H_r_i1:    h_r_i1,
		G_ri1:     g_r_i1,
		Shufflers: [][]byte{},
	}, nil
}

func segmentBitsWithPadding_MapOnCurve(data []byte) ([][]byte, error) {
	if len(data) != 256 {
		return nil, errors.New("data slice must be 256 bytes long")
	}

	segments := make([][]byte, 9)
	for i := 0; i < 8; i++ {
		segment := make([]byte, 32)
		segment[0] = 0 // Padding byte
		copy(segment[1:30], data[i*29:(i+1)*29])
		segments[i] = segment
	}

	// Last segment with 1 byte of padding, 8 bytes of data, and 24 bytes of random data
	segments[8] = make([]byte, 32)
	segments[8][0] = 0 // Padding byte
	copy(segments[8][1:25], data[232:256])

	// Fill the remaining 24 bytes with random data
	_, err := rand.Read(segments[8][25:])
	if err != nil {
		return nil, errors.New("error generating random data for the last segment")
	}

	// Fill in the last 2 bytes of the first 8 segments with the SHA256 hash of the next segment
	for i := 0; i < 8; i++ {
		hash := sha256.Sum256(segments[i+1][1:30])
		copy(segments[i][30:], hash[:2])
	}

	// map all the segments to the curve with different paddings
	for i, segment := range segments {
		// try to map to a point on the curve
		mapped_point, e := mapPointOnCurve(segment)
		if e != nil {
			fmt.Println("Error mapping point on curve:", e)
			// fmt.Println(t)
			panic(e)
		}
		segments[i] = mapped_point
		// fmt.Printf("Segment %d: %v\n", i+1, segment)
	}
	return segments, nil
}

// map a segment of the certificate on the curve
func mapPointOnCurve(data []byte) ([]byte, error) {

	// Generate a coin flip to determin whether to use positive or negative point
	result, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return nil, err // return an error if the random number generation fails
	}

	prep1 := make([]byte, 1)

	if result.Int64() == 1 {
		// Use the positive point
		prep1 = []byte{2}
	} else {
		// Use the negative point
		prep1 = []byte{3}
	}

	// prep1 := []byte{3}
	v := data
	v = append(prep1, v...)

	for i := 0; i < 256; i++ {
		v[1] = uint8(i)

		_, err := nistec.NewP256Point().SetBytes(v)
		if err == nil {
			return v, nil
		}
	}
	return nil, errors.New("no point found")
}

// / doing encrypting on the whole segment array
func EncryptSegments(h []byte, segments [][]byte) ([][]byte, error) {
	encrypted_segments := make([][]byte, len(segments))
	for i := 0; i < len(segments); i++ {
		encrypted, err := elgamal.Encrypt(h, segments[i])
		if err != nil {
			return nil, err
		}
		encrypted_segments[i] = encrypted
	}
	return encrypted_segments, nil
}

// randomInt returns a secure random integer between 0 (inclusive) and n (exclusive).
func randomInt(n int) int {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	return int(binary.BigEndian.Uint64(buf[:]) % uint64(n))
}

func removeRandomElement_int(slice []int) (int, []int) {
	index := randomInt(len(slice))
	removed := slice[index]
	return removed, append(slice[:index], slice[index+1:]...)
}

func LocatePublicKeyWithID(clientID int, ShufflerPublicKeys []*datastruct.ShufflePubKeys) (*datastruct.ShufflePubKeys, error) {
	for i := 0; i < len(ShufflerPublicKeys); i++ {
		if clientID == ShufflerPublicKeys[i].ID {
			return ShufflerPublicKeys[i], nil
		}
	}
	return nil, errors.New("Shuffler Public Key Not Found")
}

// /////screte sharing ///////
func SecreteShare(reportingClient *Client, Shuffle_PubKeys []*datastruct.ShufflePubKeys) ([]*datastruct.SecreteSharePoint, error) {

	/// start secrete sharing and store it on the auditor
	// secrete pieces has to be bigger than threshold
	scheme, err := sharing.NewShamir(reportingClient.RevealThreshold, reportingClient.TotalClients-1, reportingClient.Shamir_curve)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	key_value_scalar, err := reportingClient.Shamir_curve.NewScalar().SetBytes(reportingClient.ShuffleKey.Bytes())
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	shares, err := scheme.Split(key_value_scalar, rand.Reader)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	// fmt.Println(len(reportingClient.ShuffleKey.Bytes()))
	// fmt.Println(len(reportingClient.H_report))
	// database.Shuffle_PubKeys
	encrypt_secrete_array := []*datastruct.SecreteSharePoint{}
	/// generate a list of client ids to randomly choose from, of course the reporting client is excluded
	list_client_id := []int{}
	for i := 0; i < len(Shuffle_PubKeys); i++ {
		if Shuffle_PubKeys[i].ID != reportingClient.ID {
			list_client_id = append(list_client_id, Shuffle_PubKeys[i].ID)
		}
	}
	for i := 0; i < len(shares); i++ {
		// tag: p and y: pieces[p]
		/// remove a client to have the secrete
		var removed_client int
		removed_client, list_client_id = removeRandomElement_int(list_client_id)
		intended_client_keys, err := LocatePublicKeyWithID(removed_client, Shuffle_PubKeys)
		if err != nil {
			log.Fatalf("%v", err)
			return nil, err
		}
		intended_client_SharedSecret, err := elgamal.ECDH_bytes(intended_client_keys.DH_Pub_H, reportingClient.DH_Pub_private)
		if err != nil {
			log.Fatalf("%v", err)
			return nil, err
		}
		symmetric_key := aes.DeriveKeyFromSHA256(intended_client_SharedSecret, 16) // 16 bytes for AES-128, 24 bytes for AES-192, 32 bytes for AES-256
		// fmt.Println(symmetric_key)
		encryptedData_y, err := aes.Encrypt(shares[i].Value, symmetric_key)
		if err != nil {
			log.Fatalf("%v", err)
			return nil, err
		}
		Encrypt_piece := &datastruct.SecreteSharePoint{
			Intended_Client: removed_client,
			Tag:             shares[i].Id,
			Encrypted_y:     encryptedData_y,
		}
		encrypt_secrete_array = append(encrypt_secrete_array, Encrypt_piece)
	}

	return encrypt_secrete_array, nil
}

func ExtractCertsFromEntries(database *datastruct.Database) [][][]byte {
	res := [][][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
	}
	return res
}

func ExtractH_r_i1sFromEntries(database *datastruct.Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].H_r_i1)
	}
	return res
}

func ExtractG_ri1sFromEntries(database *datastruct.Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].G_ri1)

	}
	return res
}

func ClientGenerateChallengeEncryptionProof_NonInteractive(
	shuffling_client *Client,
	X_originals [][]byte,
	Y_originals [][]byte,
	X_primes [][]byte,
	Y_primes [][]byte,
	I1s [][]byte,
	I2s [][]byte,
) [][]byte {
	// generate the challenges
	c := [][]byte{}
	for i := 0; i < len(X_primes); i++ {
		params1 := X_originals[i]
		params2 := Y_originals[i]
		params3 := X_primes[i]
		params4 := Y_primes[i]
		params5 := I1s[i]
		params6 := I2s[i]
		params7 := shuffling_client.H_shuffle
		params8 := shuffling_client.G_shuffle

		combined := append([]byte{}, params1...)
		combined = append(combined, params2...)
		combined = append(combined, params3...)
		combined = append(combined, params4...)
		combined = append(combined, params5...)
		combined = append(combined, params6...)
		combined = append(combined, params7...)
		combined = append(combined, params8...)

		hasher := sha256.New()
		hasher.Write(combined)
		hash := hasher.Sum(nil)
		c = append(c, hash)
	}

	return c
}

// permuteByteSlicesWithMatrix takes a permutation matrix and an array of byte slices,
// then permutes the array according to the matrix.
func permuteDatabaseWithMatrix(matrix [][]int, Entries []*datastruct.ReportingEntry) ([]*datastruct.ReportingEntry, error) {
	// Check if the matrix is square and matches the length of the byte slices array
	if len(matrix) == 0 || len(matrix) != len(Entries) {
		return nil, fmt.Errorf("matrix and byte slices array size mismatch or empty matrix")
	}

	n := len(matrix)
	for _, row := range matrix {
		if len(row) != n {
			return nil, fmt.Errorf("non-square matrix")
		}
	}

	// Initialize the permuted array of byte slices
	permutedByteSlices := make([]*datastruct.ReportingEntry, n)

	// Apply the permutation described by the matrix to the byte slices
	for i, row := range matrix {
		for j, val := range row {
			if val == 1 {
				if i >= n || j >= n {
					return nil, fmt.Errorf("index out of range in permutation matrix")
				}
				permutedByteSlices[i] = Entries[j]
				break
			}
		}
	}

	return permutedByteSlices, nil
}

// permuteByteSlicesWithMatrix takes a permutation matrix and an array of byte slices,
// then permutes the array according to the matrix.
func permuteByteSlicesWithMatrix(matrix [][]int, byteSlices [][]byte) ([][]byte, error) {
	// Check if the matrix is square and matches the length of the byte slices array
	if len(matrix) == 0 || len(matrix) != len(byteSlices) {
		return nil, fmt.Errorf("matrix and byte slices array size mismatch or empty matrix")
	}

	n := len(matrix)
	for _, row := range matrix {
		if len(row) != n {
			return nil, fmt.Errorf("non-square matrix")
		}
	}

	// Initialize the permuted array of byte slices
	permutedByteSlices := make([][]byte, n)

	// Apply the permutation described by the matrix to the byte slices
	for i, row := range matrix {
		for j, val := range row {
			if val == 1 {
				if i >= n || j >= n {
					return nil, fmt.Errorf("index out of range in permutation matrix")
				}
				permutedByteSlices[i] = byteSlices[j]
				break
			}
		}
	}

	return permutedByteSlices, nil
}

func LocateShuffleOrderWithID(clientID int, Shufflers []*datastruct.ShuffleRecords) (int, error) {
	for i := 0; i < len(Shufflers); i++ {
		if clientID == Shufflers[i].ID {
			return i, nil
		}
	}
	return -1, errors.New("Shuffle order not found")
}

// flattenBytes takes a 2D slice of bytes and flattens it into a 1D slice.
func flattenBytes(twoD [][]byte) []byte {
	var oneD []byte
	for _, slice := range twoD {
		// Append each sub-slice to the new slice.
		oneD = append(oneD, slice...)
	}
	return oneD
}

// // generate the non interactive challenge, taking account of all the public parameters
func ClientGenerateChallengeShufflingProof_NonInteractive_Groth_And_Lu(
	shuffling_client *Client,
	orginal_entries [][][]byte,
	shuffled_entries [][][]byte,
	X_primes_encrypted_and_permutated [][]byte,
	Y_primes_encrypted_and_permutated [][]byte,
	commitments []*big.Int,
	Big_Vs [][]byte,
	V_prime_X []byte,
	V_prime_Y []byte,
	RSA_Q *big.Int,
	RSA_P *big.Int,
	RSA_subgroup_p_prime *big.Int,
	RSA_subgroup_q_prime *big.Int) [][]byte {
	// generate the challenges
	c := [][]byte{}
	for i := 0; i < len(orginal_entries); i++ {
		params1 := flattenBytes(orginal_entries[i])
		params2 := flattenBytes(shuffled_entries[i])
		params3 := X_primes_encrypted_and_permutated[i]
		params4 := Y_primes_encrypted_and_permutated[i]
		params5 := commitments[i]
		params6 := flattenBytes(Big_Vs)
		params7 := V_prime_X
		params8 := V_prime_Y
		params9 := RSA_Q
		params10 := RSA_P
		params11 := RSA_subgroup_p_prime
		params12 := RSA_subgroup_q_prime
		params13 := shuffling_client.H_shuffle
		params14 := shuffling_client.G_shuffle

		combined := append([]byte{}, params1...)
		combined = append(combined, params2...)
		combined = append(combined, params3...)
		combined = append(combined, params4...)
		combined = append(combined, params5.Bytes()...)
		combined = append(combined, params6...)
		combined = append(combined, params7...)
		combined = append(combined, params8...)
		combined = append(combined, params9.Bytes()...)
		combined = append(combined, params10.Bytes()...)
		combined = append(combined, params11.Bytes()...)
		combined = append(combined, params12.Bytes()...)
		combined = append(combined, params13...)
		combined = append(combined, params14...)

		hasher := sha256.New()
		hasher.Write(combined)
		hash := hasher.Sum(nil)
		c = append(c, hash)
	}

	return c
}

func ClientGenerateChallengeDecryptionProof_NonInteractive(
	shuffling_client *Client,
	rG_x [][]byte,
	rG_y [][]byte,
) [][]byte {
	// generate the challenges
	c := [][]byte{}
	for i := 0; i < len(rG_x); i++ {
		params1 := rG_x[i]
		params2 := rG_y[i]
		params3 := shuffling_client.H_shuffle
		params4 := shuffling_client.G_shuffle

		combined := append([]byte{}, params1...)
		combined = append(combined, params2...)
		combined = append(combined, params3...)
		combined = append(combined, params4...)

		hasher := sha256.New()
		hasher.Write(combined)
		hash := hasher.Sum(nil)
		c = append(c, hash)
	}

	return c
}

func (reportingClient *Client) ClientShuffle(req *datastruct.ShufflePhaseAuditorRequest, reply *datastruct.ShufflePhaseAuditorReply) error {

	start := time.Now()

	if req.Status == 0 {
		reply.Status = true
		reportingClient.ShuffleTime = 0.01
		reportingClient.ShuffleDownload = 8
		reportingClient.ShuffleUpload = 8
		return nil
	}

	reply.ShufflerID = reportingClient.ID

	reply.ZKProofs = datastruct.ZKRecords{}

	reply.ZKProofs.ShufflerID = reportingClient.ID

	database := req.Database

	X_originals := ExtractH_r_i1sFromEntries(&database)
	Y_originals := ExtractG_ri1sFromEntries(&database)
	// retrieve everything in the database
	original_entries := ExtractCertsFromEntries(&database)

	// ****** conduct proof of encryption zero knowledge proof
	r1s := [][]byte{}
	r2s := [][]byte{}
	r3s := [][]byte{}

	alphas_r_i_1_prime := [][]byte{}
	betas := [][]byte{}
	gammas := [][]byte{}

	X_primes := [][]byte{}
	Y_primes := [][]byte{}

	I1s := [][]byte{}
	I2s := [][]byte{}

	for i := 0; i < len(database.Entries); i++ {
		// r_i_0_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		r_i_1_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)

		// //////// r_i_1_prime   rolling///////
		// roll the H_r_i1 with r_i_1_prime
		rolled_H_ri1_ri_1_prime, err := elgamal.ECDH_bytes(database.Entries[i].H_r_i1, r_i_1_prime)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}

		// roll the g_r_i1 with r_i_1_prime
		rolled_g_ri1_ri_1_prime, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, r_i_1_prime)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}

		alphas_r_i_1_prime = append(alphas_r_i_1_prime, r_i_1_prime)

		beta := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		gamma := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		betas = append(betas, beta)
		gammas = append(gammas, gamma)

		X_alpha := rolled_H_ri1_ri_1_prime
		Y_alpha := rolled_g_ri1_ri_1_prime

		H_beta, err := elgamal.ECDH_bytes(reportingClient.H_shuffle, beta)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		H_Gamma, err := elgamal.ECDH_bytes(reportingClient.H_shuffle, gamma)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}

		X_prime, err := elgamal.Encrypt(X_alpha, H_beta)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		X_primes = append(X_primes, X_prime)
		Y_prime, err := elgamal.Encrypt(Y_alpha, H_Gamma)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		Y_primes = append(Y_primes, Y_prime)

		// generate I1 and I2
		r1 := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		X_r1, err := elgamal.ECDH_bytes(database.Entries[i].H_r_i1, r1)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		r1s = append(r1s, r1)

		r2 := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		H_r2, err := elgamal.ECDH_bytes(reportingClient.H_shuffle, r2)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		r2s = append(r2s, r2)

		// generate I1
		I1, err := elgamal.Encrypt(X_r1, H_r2)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		I1s = append(I1s, I1)

		Y_r1, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, r1)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}

		r3 := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		H_r3, err := elgamal.ECDH_bytes(reportingClient.H_shuffle, r3)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		r3s = append(r3s, r3)

		// generate I2
		I2, err := elgamal.Encrypt(Y_r1, H_r3)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		I2s = append(I2s, I2)

		// finally, update the entries appropriately
		database.Entries[i].H_r_i1 = rolled_H_ri1_ri_1_prime
		database.Entries[i].G_ri1 = rolled_g_ri1_ri_1_prime
	}

	// obtain the challenges from the auditor
	cs := ClientGenerateChallengeEncryptionProof_NonInteractive(reportingClient, X_originals, Y_originals, X_primes, Y_primes, I1s, I2s)

	// generate the responses
	z1s := [][]byte{}
	z2s := [][]byte{}
	z3s := [][]byte{}

	for i := 0; i < len(database.Entries); i++ {
		c_times_a := new(big.Int).Mul(zklib.SetBigIntWithBytes(cs[i]), zklib.SetBigIntWithBytes(alphas_r_i_1_prime[i]))
		r1_plus_c_times_a := new(big.Int).Add(zklib.SetBigIntWithBytes(r1s[i]), c_times_a)
		z1 := new(big.Int).Mod(r1_plus_c_times_a, elgamal.ORDER_OF_P256_big())
		z1s = append(z1s, elgamal.PadTo32Bytes(z1.Bytes()))

		c_times_b := new(big.Int).Mul(zklib.SetBigIntWithBytes(cs[i]), zklib.SetBigIntWithBytes(betas[i]))
		r2_plus_c_times_b := new(big.Int).Add(zklib.SetBigIntWithBytes(r2s[i]), c_times_b)
		z2 := new(big.Int).Mod(r2_plus_c_times_b, elgamal.ORDER_OF_P256_big())
		z2s = append(z2s, elgamal.PadTo32Bytes(z2.Bytes()))

		c_times_g := new(big.Int).Mul(zklib.SetBigIntWithBytes(cs[i]), zklib.SetBigIntWithBytes(gammas[i]))
		r3_plus_c_times_g := new(big.Int).Add(zklib.SetBigIntWithBytes(r3s[i]), c_times_g)
		z3 := new(big.Int).Mod(r3_plus_c_times_g, elgamal.ORDER_OF_P256_big())
		z3s = append(z3s, elgamal.PadTo32Bytes(z3.Bytes()))
	}

	// record the proofs
	reply.ZKProofs.EncryptionProof.Cs = cs
	reply.ZKProofs.EncryptionProof.I1s = I1s
	reply.ZKProofs.EncryptionProof.I2s = I2s
	reply.ZKProofs.EncryptionProof.X_primes = X_primes
	reply.ZKProofs.EncryptionProof.Y_primes = Y_primes
	reply.ZKProofs.EncryptionProof.Z1s = z1s
	reply.ZKProofs.EncryptionProof.Z2s = z2s
	reply.ZKProofs.EncryptionProof.Z3s = z3s
	reply.ZKProofs.EncryptionProof.X_originals = X_originals
	reply.ZKProofs.EncryptionProof.Y_originals = Y_originals

	// ****** end of zk proof of encryption for tags

	fmt.Print(reportingClient.ID)
	fmt.Println(" shuffling the entries, this is where we generate permuation matrix")

	permutationMatrix := zklib.GeneratePermutationMatrix(len(database.Entries))

	/// do the normal shuffle with the permutation matrix
	err := errors.New("new null placeholder")
	database.Entries, err = permuteDatabaseWithMatrix(permutationMatrix, database.Entries)
	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}

	// check if this is the first shuffle
	// first_shuffle := true
	// if len(database.Shufflers_info) > 0 {
	// 	// not first shuffle
	// 	first_shuffle = false
	// }

	client_count := len(database.Entries)
	database.Shufflers_info = []*datastruct.ShuffleRecords{}
	for i := 0; i < client_count; i++ {
		// should just include everyone
		client_info := &datastruct.ShuffleRecords{
			ID: i,
		}
		database.Shufflers_info = append(database.Shufflers_info, client_info)
	}

	//  **** perform actual shuffling
	R_l_k := make([][][]byte, len(database.Entries))
	// randomize the entries/ encrypt the entries
	for i := 0; i < len(database.Entries); i++ {
		rk := [][]byte{}
		// encrypt and append g_r_i_k
		// r_i_k := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		// g_r_i_k, err := elgamal.ECDH_bytes(reportingClient.G_shuffle, r_i_k)
		// if err != nil {
		// 	log.Fatalf("%v", err)
		// 	reply.Status = false
		// 	return err
		// }
		// // append the g_r_i_k to the entry shufflers
		// database.Entries[i].Shufflers = append(database.Entries[i].Shufflers, g_r_i_k)
		// shared_h_r_i_k, err := elgamal.ECDH_bytes(g_r_i_k, reportingClient.ShuffleKey.Bytes())
		// if err != nil {
		// 	log.Fatalf("%v", err)
		// 	reply.Status = false
		// 	return err
		// }
		// /// encrypt the entry again with the shared key
		// database.Entries[i].Cert_times_h_r10, err = EncryptSegments(shared_h_r_i_k, database.Entries[i].Cert_times_h_r10)
		// if err != nil {
		// 	log.Fatalf("%v", err)
		// 	reply.Status = false
		// 	return err
		// }
		// // fmt.Println(len(database.Entries[i].Shufflers))
		// if !first_shuffle {
		/// not the first shuffle, re-randomize the previous shufflers
		for j := 0; j < len(database.Entries[i].Shufflers); j++ {
			shuffler_info := database.Shufflers_info[j]
			keys, err := LocatePublicKeyWithID(shuffler_info.ID, database.Shuffle_PubKeys)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			r_i_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
			rk = append(rk, r_i_prime)
			g_r_i_prime, err := elgamal.ECDH_bytes(keys.G_i, r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			/// changing the shuffler entry
			order, err := LocateShuffleOrderWithID(shuffler_info.ID, database.Shufflers_info)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			database.Entries[i].Shufflers[order], err = elgamal.Encrypt(database.Entries[i].Shufflers[order], g_r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			/// changing the msg entry
			h_r_i_prime, err := elgamal.ECDH_bytes(keys.H_i, r_i_prime)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			database.Entries[i].Cert_times_h_r10, err = EncryptSegments(h_r_i_prime, database.Entries[i].Cert_times_h_r10)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
		}
		// }
		// rk = append(rk, r_i_k)
		R_l_k[i] = rk
	}

	/// append the client info
	// client_count := len(database.Entries)
	// database.Shufflers_info = []*datastruct.ShuffleRecords{}
	// for i := 0; i < client_count; i++ {
	// 	// should just include everyone
	// 	client_info := &datastruct.ShuffleRecords{
	// 		ID: i,
	// 	}
	// 	database.Shufflers_info = append(database.Shufflers_info, client_info)
	// }

	// database.Shufflers_info = append(database.Shufflers_info, client_info)

	// *** zero knowledge shuffling proof
	inverse_permutationMatrix, err := zklib.InversePermutationMatrix(permutationMatrix)
	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}
	// fmt.Println(reportingClient.H_shuffle)

	X_primes_permutated, err := permuteByteSlicesWithMatrix(permutationMatrix, X_primes)
	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}
	Y_primes_permutated, err := permuteByteSlicesWithMatrix(permutationMatrix, Y_primes)
	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}

	// reencryt tags (X_prime, Y_prime) and permute them with the matrix
	X_primes_encrypted_and_permutated := [][]byte{}
	Y_primes_encrypted_and_permutated := [][]byte{}
	R_primes := [][]byte{}
	for i := 0; i < len(X_primes_permutated); i++ {
		R_prime := elgamal.Generate_Random_Dice_seed(reportingClient.Curve)
		R_primes = append(R_primes, R_prime)

		H_R_prime, err := elgamal.ECDH_bytes(reportingClient.H_shuffle, R_prime)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		X_prime_encrypted_and_permutated, err := elgamal.Encrypt(X_primes_permutated[i], H_R_prime)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		X_primes_encrypted_and_permutated = append(X_primes_encrypted_and_permutated, X_prime_encrypted_and_permutated)

		Y_prime_encrypted_and_permutated, err := elgamal.Encrypt(Y_primes_permutated[i], H_R_prime)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		Y_primes_encrypted_and_permutated = append(Y_primes_encrypted_and_permutated, Y_prime_encrypted_and_permutated)
	}

	// R_R mean B in the paper btw
	// generate commitments
	// security parameters
	// Generate a permutation matrix of size 5.
	n := len(database.Entries) // matrix size
	l_t := 160
	l_s := 16 // a small security parameter
	p, q, p_prime, q_prime := database.RSA_P, database.RSA_Q, database.RSA_subgroup_p_prime, database.RSA_subgroup_q_prime
	// fmt.Println(p, q, p_prime, q_prime)
	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}
	// fmt.Println("Found the group and subgroup primes.")
	N := new(big.Int).Mul(p, q)
	// fmt.Println(N)
	order_of_g := new(big.Int).Mul(p_prime, q_prime)
	l_r := order_of_g.BitLen() // the order of the unique subgroup can be huge so IDK what to put here
	// fmt.Println("Security parameter l_r order of g", order_of_g.BitLen())
	l_s_plus_l_r := l_s + l_r

	gs := zklib.SampleNGenerators(p_prime, q_prime, n+2)
	// fmt.Println(gs)

	// generating ds
	ds := make([]*big.Int, n)
	dj := big.NewInt(0)
	dn := big.NewInt(0)
	for i := 0; i < n; i++ {
		if i == n-1 {
			ds[i] = dn
		} else {
			d, _ := zklib.GenerateSecureRandomBits(l_t + 8)
			ds[i] = zklib.SetBigIntWithBytes(d)
			dn = new(big.Int).Add(dn, new(big.Int).Neg(ds[i]))
		}

		dj = new(big.Int).Add(dj, new(big.Int).Mul(ds[i], ds[i]))
	}

	// generate commitments
	commitments := make([]*big.Int, n+1)
	rs := make([]*big.Int, 0)
	for i := 0; i <= n; i++ {
		if i == n {
			new_r, err := zklib.GenerateSecureRandomBits(l_t + l_s_plus_l_r)
			if err != nil {
				panic(err)
			}
			commitments[i] = zklib.Generate_commitment(gs, ds, dj, new_r, N)
			rs = append(rs, zklib.SetBigIntWithBytes(new_r))
		} else {
			new_r, err := zklib.GenerateSecureRandomBits(l_r)
			if err != nil {
				panic(err)
			}
			backward_index, _ := zklib.BackwardMapping(i, permutationMatrix)
			d_needed := ds[backward_index]
			d_needed = new(big.Int).Mul(d_needed, big.NewInt(2))
			commitments[i] = zklib.Generate_commitment(gs, zklib.IntToBigInt(inverse_permutationMatrix[i]), d_needed, new_r, N) // Fix: Add N as the last argument
			rs = append(rs, zklib.SetBigIntWithBytes(new_r))                                                                    // Fix: Assign the result of append to rs
		}
	}

	shuffled_entries := ExtractCertsFromEntries(&database)

	/// generating V_primes, there are two of them, so we have V_prime_X and V_prime_Y
	// R_R mean B in the paper btw
	B_prime, err := zklib.GenerateSecureRandomBits(l_s_plus_l_r + l_t)
	if err != nil {
		panic(err)
	}

	V_prime_X_pos, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(reportingClient.H_shuffle, B_prime) /// encrypting the zero element
	if err != nil {
		panic(err)
	}
	V_prime_X, err := elgamal.ReturnNegative(V_prime_X_pos)
	if err != nil {
		panic(err)
	}

	for i := 0; i < n; i++ {
		X_primes_encrypted_and_permutated_i_d_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(X_primes_encrypted_and_permutated[i], ds[i].Bytes())
		if err != nil {
			panic(err)
		}
		if ds[i].Cmp(big.NewInt(0)) < 0 {
			// fmt.Println("detected negative ds[i] V_prime_X")
			X_primes_encrypted_and_permutated_i_d_i, err = elgamal.ReturnNegative(X_primes_encrypted_and_permutated_i_d_i)
			if err != nil {
				panic(err)
			}
		}
		V_prime_X, err = elgamal.Encrypt(V_prime_X, X_primes_encrypted_and_permutated_i_d_i)
		if err != nil {
			panic(err)
		}
	}

	V_prime_Y_pos, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(reportingClient.H_shuffle, B_prime)
	if err != nil {
		panic(err)
	}

	V_prime_Y, err := elgamal.ReturnNegative(V_prime_Y_pos)
	if err != nil {
		panic(err)
	}

	for i := 0; i < n; i++ {
		Y_primes_encrypted_and_permutated_i_d_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(Y_primes_encrypted_and_permutated[i], ds[i].Bytes())
		if err != nil {
			panic(err)
		}
		if ds[i].Cmp(big.NewInt(0)) < 0 {
			// fmt.Println("detected negative ds[i] V_prime_Y")
			Y_primes_encrypted_and_permutated_i_d_i, err = elgamal.ReturnNegative(Y_primes_encrypted_and_permutated_i_d_i)
			if err != nil {
				panic(err)
			}
		}
		V_prime_Y, err = elgamal.Encrypt(V_prime_Y, Y_primes_encrypted_and_permutated_i_d_i)
		if err != nil {
			panic(err)
		}
	}

	// generate the Big_V for the entries
	// we have one V for each segment of the entry
	Big_Vs := [][]byte{}
	// init the Vs
	for i := 0; i < len(database.Entries[0].Cert_times_h_r10); i++ {
		Big_Vs = append(Big_Vs, elgamal.ReturnZeroPoint())
	}
	// adding up the Ci_di
	for i := 0; i < n; i++ {
		for j := 0; j < len(database.Entries[0].Cert_times_h_r10); j++ {
			Ci_di, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(database.Entries[i].Cert_times_h_r10[j], ds[i].Bytes())
			if err != nil {
				panic(err)
			}
			if ds[i].Cmp(big.NewInt(0)) < 0 {
				// fmt.Println("detected negative ds[i]")
				Ci_di, err = elgamal.ReturnNegative(Ci_di)
				if err != nil {
					panic(err)
				}
			}
			Big_Vs[j], err = elgamal.Encrypt(Big_Vs[j], Ci_di)
		}
	}

	// Bs are R_R in the paper
	// calculate all public keys
	Bs := [][]byte{}
	for i := 0; i < len(database.Shufflers_info); i++ {
		B, err := zklib.GenerateSecureRandomBits(l_s_plus_l_r + l_t)
		if err != nil {
			panic(err)
		}
		Bs = append(Bs, B)
	}
	for i := 0; i < len(database.Shufflers_info); i++ {
		for j := 0; j < len(database.Entries[0].Cert_times_h_r10); j++ {
			keys, err := LocatePublicKeyWithID(database.Shufflers_info[i].ID, database.Shuffle_PubKeys)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			// add negative encryption with this public key
			Enc_B_pos, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(keys.H_i, Bs[i])
			Enc_B, err := elgamal.ReturnNegative(Enc_B_pos)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			Big_Vs[j], err = elgamal.Encrypt(Big_Vs[j], Enc_B)
		}
	}
	// fmt.Println(len(Bs) == len(database.Shufflers_info))
	// submit shuffled entries, tags(X_primes_encrypted_and_permutated, Y_primes_encrypted_and_permutated), commitments, and Vs to the auditor
	// auditor will in turn, generate the challenges
	lambdas := ClientGenerateChallengeShufflingProof_NonInteractive_Groth_And_Lu(
		reportingClient,
		original_entries,                  // original_entries [][][]byte,
		shuffled_entries,                  // 	shuffled_entries [][][]byte,
		X_primes_encrypted_and_permutated, // X_primes_encrypted_and_permutated [][]byte,
		Y_primes_encrypted_and_permutated, // Y_primes_encrypted_and_permutated [][]byte,
		commitments,                       // commitments []*big.Int,
		Big_Vs,                            // Big_Vs [][]byte,
		V_prime_X,                         // V_prime_X []byte,
		V_prime_Y,                         // V_prime_Y []byte,
		q,                                 // RSA_Q *big.Int,
		p,                                 // RSA_P *big.Int,
		p_prime,                           // RSA_subgroup_p_prime *big.Int,
		q_prime)                           // RSA_subgroup_q_prime *big.Int,
	// gs,                                // RSA_subgroup_generators []*big.Int,
	// database.Shufflers_info)           // Updated_Shufflers_info []*ShuffleRecords

	if err != nil {
		log.Fatalf("%v", err)
		reply.Status = false
		return err
	}
	// generate the replys
	fs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		t_pi_j, _ := zklib.ForwardMapping(i, permutationMatrix)
		fs[i] = new(big.Int).Add(zklib.SetBigIntWithBytes(lambdas[t_pi_j]), ds[i])
	}

	small_z := big.NewInt(0)
	for i := 0; i < n; i++ {
		small_z = new(big.Int).Add(small_z, new(big.Int).Mul(zklib.SetBigIntWithBytes(lambdas[i]), rs[i]))
	}
	small_z = new(big.Int).Add(small_z, rs[n])

	/// generate Z_ks **** hard part
	Z_ks := [][]byte{}
	// fmt.Println(len(R_l_k))
	// fmt.Println(len(R_l_k[0]))
	// fmt.Println(len(Bs))
	for k := 0; k < len(database.Shufflers_info); k++ {
		Z_k := zklib.SetBigIntWithBytes(Bs[k])
		for l := 0; l < n; l++ {
			R_l_k_one := zklib.SetBigIntWithBytes(R_l_k[l][k])
			pi_l, err := zklib.ForwardMapping(l, permutationMatrix)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return err
			}
			lambda_pi_l_times_R_l_k := new(big.Int).Mul(zklib.SetBigIntWithBytes(lambdas[pi_l]), R_l_k_one)
			Z_k = new(big.Int).Add(Z_k, lambda_pi_l_times_R_l_k)
		}
		Z_ks = append(Z_ks, Z_k.Bytes())
	}

	/// generate Z_prime
	Z_prime := zklib.SetBigIntWithBytes(B_prime)

	for i := 0; i < n; i++ {
		pi_l, err := zklib.ForwardMapping(i, permutationMatrix)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		lambda_pi_l_times_R_prime := new(big.Int).Mul(zklib.SetBigIntWithBytes(lambdas[pi_l]), zklib.SetBigIntWithBytes(R_primes[i]))
		Z_prime = new(big.Int).Add(Z_prime, lambda_pi_l_times_R_prime)
	}

	reply.ZKProofs.ShuffleProof.EntriesBeforeShuffle = original_entries
	reply.ZKProofs.ShuffleProof.EntriesAfterShuffle = shuffled_entries
	reply.ZKProofs.ShuffleProof.X_primes_encrypted_and_permutated_tagX = X_primes_encrypted_and_permutated
	reply.ZKProofs.ShuffleProof.Y_primes_encrypted_and_permutated_tagY = Y_primes_encrypted_and_permutated
	reply.ZKProofs.ShuffleProof.Commitments = commitments
	reply.ZKProofs.ShuffleProof.Big_Vs = Big_Vs
	reply.ZKProofs.ShuffleProof.V_prime_X = V_prime_X
	reply.ZKProofs.ShuffleProof.V_prime_Y = V_prime_Y
	reply.ZKProofs.ShuffleProof.ChallengesLambda = lambdas
	reply.ZKProofs.ShuffleProof.Fs = fs
	reply.ZKProofs.ShuffleProof.SmallZ = small_z
	reply.ZKProofs.ShuffleProof.Z_ks = Z_ks
	reply.ZKProofs.ShuffleProof.Z_prime = Z_prime
	reply.ZKProofs.ShuffleProof.RSA_subgroup_generators = gs
	reply.ZKProofs.ShuffleProof.Updated_Shufflers_info = database.Shufflers_info

	// *** zero knowledge Proof of Knowledge decryption
	// submit the rG and commitment of decryption to the auditor
	// rG for x is (alpha + beta)G
	// rG for y is (alpha + gamma)G

	// generate the rG for x and y
	rG_x := [][]byte{}
	rG_y := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		r_prime_g, err := elgamal.ECDH_bytes(reportingClient.G_shuffle, R_primes[i])
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		beta, err := elgamal.ECDH_bytes(reportingClient.G_shuffle, betas[i])
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		gamma, err := elgamal.ECDH_bytes(reportingClient.G_shuffle, gammas[i])
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		x, err := elgamal.Encrypt(r_prime_g, beta)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		y, err := elgamal.Encrypt(r_prime_g, gamma)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return err
		}
		rG_x = append(rG_x, x)
		rG_y = append(rG_y, y)
	}

	// submit the rG_x and rG_y to the auditor
	challenges := ClientGenerateChallengeDecryptionProof_NonInteractive(reportingClient, rG_x, rG_y)

	// compute S for x and y
	// s=r+c*private_key
	S_x := [][]byte{}
	S_y := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		c_times_private_key := new(big.Int).Mul(zklib.SetBigIntWithBytes(challenges[i]), zklib.SetBigIntWithBytes(reportingClient.ShuffleKey.Bytes()))
		s_x := new(big.Int).Add(zklib.SetBigIntWithBytes(R_primes[i]), c_times_private_key)
		s_x = new(big.Int).Add(zklib.SetBigIntWithBytes(betas[i]), s_x)

		s_y := new(big.Int).Add(zklib.SetBigIntWithBytes(R_primes[i]), c_times_private_key)
		s_y = new(big.Int).Add(zklib.SetBigIntWithBytes(gammas[i]), s_y)

		S_x = append(S_x, elgamal.PadTo32Bytes(s_x.Bytes()))
		S_y = append(S_y, elgamal.PadTo32Bytes(s_y.Bytes()))
	}

	// just record it
	reply.ZKProofs.DecryptionProof.Challenges = challenges
	reply.ZKProofs.DecryptionProof.Ss_X = S_x
	reply.ZKProofs.DecryptionProof.Ss_Y = S_y
	reply.ZKProofs.DecryptionProof.RG_X = rG_x
	reply.ZKProofs.DecryptionProof.RG_Y = rG_y

	reply.Database = database
	//**** end of the zero knowledge Proof of Knowledge decryption Done!
	reply.Status = true

	total_time := time.Since(start)
	reportingClient.ShuffleTime = total_time.Seconds()

	shuffle_up, err := json.Marshal(reply)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}

	reportingClient.ShuffleUpload = len(shuffle_up)

	shuffle_down, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("Error serializing to JSON: %v", err)
	}

	reportingClient.ShuffleDownload = len(shuffle_down)

	return nil
}

func ClientReveal(reportingClient *Client, database datastruct.Database, zkdatabase []*datastruct.ZKRecords) (datastruct.RevealPhaseReportRevealRequest, error) {

	// check the zk proof first

	/// untrim the zkrecords to fit in the function
	fmt.Println("Performing verification checks of ", len(zkdatabase), " zk proofs for client ", reportingClient.ID)
	for i := 0; i < len(zkdatabase); i++ {
		if i != len(zkdatabase)-1 {
			zkdatabase[i].ShuffleProof.EntriesAfterShuffle = zkdatabase[i+1].ShuffleProof.EntriesBeforeShuffle
		}
		if !CheckZKProofForOne(zkdatabase[i], database) {
			fmt.Println("ZK proof failed for client", reportingClient.ID)
			return datastruct.RevealPhaseReportRevealRequest{
				ShufflerID:    reportingClient.ID,
				RevealRecords: datastruct.DecryptRecords{},
			}, nil
		}
	}

	fmt.Println("ZK proof passed for client", reportingClient.ID)

	req := datastruct.RevealPhaseReportRevealRequest{
		ShufflerID:    reportingClient.ID,
		RevealRecords: datastruct.DecryptRecords{},
	}

	revealRecords := &datastruct.DecryptRecords{
		ShufflerID: reportingClient.ID,
		Keys:       [][]byte{},
	}
	order, err := LocateShuffleOrderWithID(reportingClient.ID, database.Shufflers_info)
	if err != nil {
		log.Fatalf("%v", err)
		return req, err
	}
	for i := 0; i < len(database.Entries); i++ {
		// check if this is my entry
		h_test, err := elgamal.ECDH_bytes(database.Entries[i].G_ri1, reportingClient.ReportingKey.Bytes())
		if err != nil {
			log.Fatalf("%v", err)
			return req, err
		}

		if bytes.Equal(h_test, database.Entries[i].H_r_i1) {
			// it is my entry
			fmt.Print(reportingClient.ID)
			fmt.Println(" found entry")

			g_first_term_with_shuffle_key, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[order], reportingClient.ShuffleKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return req, err
			}

			g_second_term_with_reporting_key, err := elgamal.ECDH_bytes(reportingClient.InitialG_ri0, reportingClient.ReportingKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return req, err
			}
			reveal_value_self, err := elgamal.Encrypt(g_first_term_with_shuffle_key, g_second_term_with_reporting_key)

			if err != nil {
				log.Fatalf("%v", err)
				return req, err
			}
			revealRecords.Keys = append(revealRecords.Keys, reveal_value_self)
		} else {
			// it is not
			reveal_value_non_self, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[order], reportingClient.ShuffleKey.Bytes())
			if err != nil {
				log.Fatalf("%v", err)
				return req, err
			}
			revealRecords.Keys = append(revealRecords.Keys, reveal_value_non_self)
		}

	}
	req.RevealRecords = *revealRecords
	return req, nil
}

// //client reports to the auditor with decryption
func ClientReportDecryptedSecret(client *Client, missingClientID int, database datastruct.Database) (*datastruct.SecreteShareDecrypt, error) {
	/// find missing client's intended secrete piece
	secretes := database.SecreteShareMap[missingClientID]
	var missingClientPiece *datastruct.SecreteSharePoint
	for i := 0; i < len(secretes); i++ {
		if secretes[i].Intended_Client == client.ID {
			missingClientPiece = secretes[i]
		}
	}
	if missingClientPiece == nil {
		// this client was not shared with a secrete
		return nil, nil
	}
	/// find the missing client's pub key
	missingClientPubKey, err := LocatePublicKeyWithID(missingClientID, database.Shuffle_PubKeys)
	if err != nil {
		log.Fatalf("client pubkey not found %v", err)
		return nil, err
	}
	/// find the missing client's shuffling order
	missingClientShuffleOrder, err := LocateShuffleOrderWithID(missingClientID, database.Shufflers_info)
	if err != nil {
		log.Fatalf("client Shuffle order not found %v", err)
		return nil, err
	}
	// compute d_j_i with for each database entry and return to auditor
	shared_secrete, err := elgamal.ECDH_bytes(missingClientPubKey.DH_Pub_H, client.DH_Pub_private)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	symmetric_key := aes.DeriveKeyFromSHA256(shared_secrete, 16)
	// fmt.Println(symmetric_key)
	decrypted_y, err := aes.Decrypt(missingClientPiece.Encrypted_y, symmetric_key)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}

	res_d_j_i := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		/// compute while treating the secrete piece as a piece
		d_ji, err := elgamal.ECDH_bytes(database.Entries[i].Shufflers[missingClientShuffleOrder], decrypted_y)
		if err != nil {
			log.Fatalf("secrete piece compute issue %v", err)
			return nil, err
		}
		res_d_j_i = append(res_d_j_i, d_ji)
	}

	return &datastruct.SecreteShareDecrypt{
		Tag:           missingClientPiece.Tag,
		DecryptPieces: res_d_j_i,
	}, nil
}

func CheckZKProofForOne(zkproof *datastruct.ZKRecords, database datastruct.Database) bool {
	// verify the zk proof that the client provided
	uploaded_zk := zkproof

	// encryption check
	// checks sG=rG+cH
	proving_client := zkproof.ShufflerID
	pubkeys_client, err := LocatePublicKeyWithID(proving_client, database.Shuffle_PubKeys)
	if err != nil {
		log.Fatalf("%v", err)
		return false
	}

	z1s := uploaded_zk.EncryptionProof.Z1s
	z2s := uploaded_zk.EncryptionProof.Z2s
	z3s := uploaded_zk.EncryptionProof.Z3s

	// fmt.Println(S_x)
	for i := 0; i < len(z1s); i++ {
		// first challenge
		X_z1, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.X_originals[i], z1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		H_z2, err := elgamal.ECDH_bytes(pubkeys_client.H_i, z2s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		first_challenge_left_hand, err := elgamal.Encrypt(X_z1, H_z2)
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		X_prime_c, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.X_primes[i], uploaded_zk.EncryptionProof.Cs[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}
		first_challenge_right_hand, err := elgamal.Encrypt(X_prime_c, uploaded_zk.EncryptionProof.I1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		if !bytes.Equal(first_challenge_left_hand, first_challenge_right_hand) {
			fmt.Println("First challenge failed for client", proving_client)
			// reply.Status = false
			return false
		}
		// else {
		// 	fmt.Println("First challenge PASSED for client", proving_client.ID)
		// }

		// second challenge
		Y_z1, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.Y_originals[i], z1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		H_z3, err := elgamal.ECDH_bytes(pubkeys_client.H_i, z3s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		second_challenge_left_hand, err := elgamal.Encrypt(Y_z1, H_z3)
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		Y_prime_c, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.Y_primes[i], uploaded_zk.EncryptionProof.Cs[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}
		second_challenge_right_hand, err := elgamal.Encrypt(Y_prime_c, uploaded_zk.EncryptionProof.I2s[i])
		if err != nil {
			log.Fatalf("%v", err)
			// reply.Status = false
			return false
		}

		if !bytes.Equal(second_challenge_left_hand, second_challenge_right_hand) {
			fmt.Println("Second challenge failed for client", proving_client)
			// reply.Status = false
			return false
		}
		// else {
		// 	fmt.Println("Second challenge PASSED for client", proving_client.ID)
		// }

	}

	fmt.Println("ZK Proof for encryption is verified for client ", proving_client)
	// ********* shuffle check
	n := len(uploaded_zk.ShuffleProof.EntriesAfterShuffle)
	gs := uploaded_zk.ShuffleProof.RSA_subgroup_generators
	N := new(big.Int).Mul(database.RSA_P, database.RSA_Q)
	// first check
	ts := uploaded_zk.ShuffleProof.ChallengesLambda
	// / sum up fs and check if it is equal to sum of ts
	sum := big.NewInt(0)

	fs := uploaded_zk.ShuffleProof.Fs
	small_z := uploaded_zk.ShuffleProof.SmallZ
	Z_ks := uploaded_zk.ShuffleProof.Z_ks
	Z_prime := uploaded_zk.ShuffleProof.Z_prime
	for _, f := range fs {
		sum.Add(sum, f)
	}
	sum_ts := big.NewInt(0)
	for _, t := range ts {
		sum_ts.Add(sum_ts, zklib.SetBigIntWithBytes(t))
	}
	// fmt.Println("Sum of fs:", sum)
	// fmt.Println("Sum of ts:", sum_ts)
	if sum.Cmp(sum_ts) == 0 {
		fmt.Println("First Test PASSED!!!!!!!!!Sum of fs is equal to sum of ts")
	} else {
		fmt.Println("Sum of fs is not equal to sum of ts")
		// reply.Status = false
		return false
	}

	// second check
	// calculate f_delta
	f_delta := big.NewInt(0)
	// sum of f squared
	for _, f := range fs {
		f_delta.Add(f_delta, new(big.Int).Mul(f, f))
	}
	// minus sum of ts squared
	for _, t := range ts {
		f_delta.Sub(f_delta, new(big.Int).Mul(zklib.SetBigIntWithBytes(t), zklib.SetBigIntWithBytes(t)))
	}

	// / conducting second check
	second_condition_right_hand_side := zklib.Generate_commitment(gs, fs, f_delta, small_z.Bytes(), N)
	// fmt.Print("second_condition_right_hand_side ")
	// fmt.Println(second_condition_right_hand_side)
	second_condition_left_hand_side := new(big.Int).Set(uploaded_zk.ShuffleProof.Commitments[n])
	for i := 0; i < n; i++ {
		second_condition_left_hand_side = new(big.Int).Mul(second_condition_left_hand_side, new(big.Int).Exp(uploaded_zk.ShuffleProof.Commitments[i], zklib.SetBigIntWithBytes(ts[i]), N))
	}
	second_condition_left_hand_side = new(big.Int).Mod(second_condition_left_hand_side, N)

	// fmt.Print("second_condition_left_hand_side ")
	// fmt.Println(second_condition_left_hand_side)
	// compare the two sides
	if second_condition_left_hand_side.Cmp(second_condition_right_hand_side) == 0 {
		fmt.Println("Second Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("they are not equal! Failed???????")
		// reply.Status = false
		return false
	}

	// third check for the entries **** hardest part brutal
	// k means the index for individual pieces of the entry
	for k := 0; k < len(uploaded_zk.ShuffleProof.EntriesAfterShuffle[0]); k++ {
		third_check_left_hand_side := elgamal.ReturnInfinityPoint()
		for i := 0; i < n; i++ {
			C_i := uploaded_zk.ShuffleProof.EntriesAfterShuffle[i][k]
			C_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(C_i, fs[i].Bytes())
			if err != nil {
				panic(err)
			}
			// check if fs[i] is negative
			if fs[i].Cmp(big.NewInt(0)) < 0 {
				// fmt.Println("detected negative fs[i]")
				C_i_f_i, err = elgamal.ReturnNegative(C_i_f_i)
				if err != nil {
					panic(err)
				}
			}
			third_check_left_hand_side, err = elgamal.Encrypt(third_check_left_hand_side, C_i_f_i)
			if err != nil {
				panic(err)
			}
		}

		third_check_right_hand_side := uploaded_zk.ShuffleProof.Big_Vs[k]
		for i := 0; i < n; i++ {
			c_i := uploaded_zk.ShuffleProof.EntriesBeforeShuffle[i][k]
			c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(c_i, ts[i])
			if err != nil {
				panic(err)
			}
			third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, c_i_lambda_i)
		}
		// find the public key of the shuffler
		for i := 0; i < len(uploaded_zk.ShuffleProof.Updated_Shufflers_info); i++ {
			updated_shufflers := uploaded_zk.ShuffleProof.Updated_Shufflers_info[i]
			shuffler_keys, err := LocatePublicKeyWithID(updated_shufflers.ID, database.Shuffle_PubKeys)
			if err != nil {
				panic(err)
			}
			encrypted_one_with_Z_k, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_ks[i])
			if err != nil {
				panic(err)
			}
			third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, encrypted_one_with_Z_k)
			if err != nil {
				panic(err)
			}
		}

		// compare the two sides
		if !bytes.Equal(third_check_left_hand_side, third_check_right_hand_side) {
			fmt.Println("Third Test FAILED????????", k)
			// reply.Status = false
			return false
		}
	}
	fmt.Println("Third Test concerning the cyphertext shuffling PASSED!!!!!!!!!")

	// fourth check for tag X
	fourth_condition_left_hand_side := elgamal.ReturnInfinityPoint()

	for i := 0; i < n; i++ {
		T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(uploaded_zk.ShuffleProof.X_primes_encrypted_and_permutated_tagX[i], fs[i].Bytes())
		if err != nil {
			panic(err)
		}
		// check if fs[i] is negative
		if fs[i].Cmp(big.NewInt(0)) < 0 {
			// fmt.Println("detected negative fs[i]")
			T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
			if err != nil {
				panic(err)
			}
		}
		fourth_condition_left_hand_side, err = elgamal.Encrypt(fourth_condition_left_hand_side, T_i_f_i)
		if err != nil {
			panic(err)
		}
	}
	fourth_condition_right_hand_side := uploaded_zk.ShuffleProof.V_prime_X
	// find the public key of the shuffler
	shuffler_keys, err := LocatePublicKeyWithID(uploaded_zk.ShufflerID, database.Shuffle_PubKeys)
	// fmt.Println("found this guys id ", uploaded_zk.ShufflerID)
	if err != nil {
		panic(err)
	}
	encrypted_one_with_Z_prime, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_prime.Bytes())
	// fmt.Println(shuffler_keys.H_i)
	if err != nil {
		panic(err)
	}
	fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, encrypted_one_with_Z_prime)
	if err != nil {
		panic(err)
	}
	lambdas := ts
	tags_before_shuffle := uploaded_zk.EncryptionProof.X_primes
	for i := 0; i < n; i++ {
		small_c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle[i], lambdas[i])
		if err != nil {
			panic(err)
		}
		fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, small_c_i_lambda_i)
		if err != nil {
			panic(err)
		}
	}
	// compare the two sides
	if bytes.Equal(fourth_condition_left_hand_side, fourth_condition_right_hand_side) {
		fmt.Println("Fourth Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("Fourth Test FAILED????????")
		// reply.Status = false
		return false
	}

	// fitfh check for tag Y
	fifth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(uploaded_zk.ShuffleProof.Y_primes_encrypted_and_permutated_tagY[i], fs[i].Bytes())
		if err != nil {
			panic(err)
		}
		// check if fs[i] is negative
		if fs[i].Cmp(big.NewInt(0)) < 0 {
			// fmt.Println("detected negative fs[i]")
			T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
			if err != nil {
				panic(err)
			}
		}
		fifth_condition_left_hand_side, err = elgamal.Encrypt(fifth_condition_left_hand_side, T_i_f_i)
		if err != nil {
			panic(err)
		}
	}
	fifth_condition_right_hand_side := uploaded_zk.ShuffleProof.V_prime_Y

	fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, encrypted_one_with_Z_prime)
	if err != nil {
		panic(err)
	}
	// lambdas := ts
	tags_before_shuffle_Y := uploaded_zk.EncryptionProof.Y_primes
	for i := 0; i < n; i++ {
		small_C_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle_Y[i], lambdas[i])
		if err != nil {
			panic(err)
		}
		fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, small_C_i_lambda_i)
		if err != nil {
			panic(err)
		}
	}
	// compare the two sides
	if bytes.Equal(fifth_condition_left_hand_side, fifth_condition_right_hand_side) {
		fmt.Println("Fifth Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("Fifth Test FAILED????????")
		// reply.Status = false
		return false
	}

	return true
}
