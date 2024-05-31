package datastruct

import (
	"crypto/ecdh"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// h = g^x where x is the private key
type ReportingEntry struct {
	Cert_times_h_r10 [][]byte
	// G_ri0            []byte
	H_r_i1    []byte
	G_ri1     []byte
	Shufflers [][]byte
}

type Database struct {
	// RSA public params
	RSA_P                *big.Int
	RSA_Q                *big.Int
	RSA_subgroup_p_prime *big.Int
	RSA_subgroup_q_prime *big.Int
	// actual entries
	Entries         []*ReportingEntry
	Shufflers_info  []*ShuffleRecords
	Decrypt_info    []*DecryptRecords
	Shuffle_PubKeys []*ShufflePubKeys
	SecreteShareMap map[int][]*SecreteSharePoint
	FT_Info         [][]SecreteShareDecrypt
	// ZK_info         []*ZKRecords
}

type ZKDatabase struct {
	ZK_info []*ZKRecords
}

type ZKRecords struct {
	ShufflerID      int
	EncryptionProof EcryptionProofRecord
	ShuffleProof    ShuffleProofRecord
	DecryptionProof DecryptionProofRecord
}

type DecryptionProofRecord struct {
	RG_X       [][]byte
	RG_Y       [][]byte
	Challenges [][]byte
	Ss_X       [][]byte
	Ss_Y       [][]byte
}

type EcryptionProofRecord struct {
	X_originals [][]byte
	Y_originals [][]byte
	X_primes    [][]byte
	Y_primes    [][]byte
	I1s         [][]byte
	I2s         [][]byte
	Cs          [][]byte
	Z1s         [][]byte
	Z2s         [][]byte
	Z3s         [][]byte
}

type ShuffleProofRecord struct {
	// recorded before shuffle
	EntriesBeforeShuffle    [][][]byte
	RSA_subgroup_generators []*big.Int
	// commitment
	EntriesAfterShuffle                    [][][]byte
	X_primes_encrypted_and_permutated_tagX [][]byte
	Y_primes_encrypted_and_permutated_tagY [][]byte
	Commitments                            []*big.Int
	Big_Vs                                 [][]byte
	V_prime_X                              []byte
	V_prime_Y                              []byte
	Updated_Shufflers_info                 []*ShuffleRecords
	//challenges
	ChallengesLambda [][]byte
	// Responses
	Fs      []*big.Int
	SmallZ  *big.Int
	Z_ks    [][]byte
	Z_prime *big.Int
}

type ShuffleRecords struct {
	ID int
	// H_i []byte
	// G_i []byte
}

type SecreteSharePoint struct {
	Intended_Client int
	Tag             uint32
	Encrypted_y     []byte
}

type ShufflePubKeys struct {
	ID       int
	H_i      []byte
	G_i      []byte
	DH_Pub_H []byte
}

type DecryptRecords struct {
	ShufflerID int
	Keys       [][]byte
}

type Auditor struct {
	FileName         string
	ZKFileName       string
	Curve            ecdh.Curve
	Shamir_pieces    uint32
	Shamir_threshold uint32
	Shamir_curve     *curves.Curve
}

type SecreteShareDecrypt struct {
	Tag           uint32
	DecryptPieces [][]byte
}

type RegistrationRequest struct {
	H_shuffle []byte
	G_shuffle []byte
	DH_Pub_H  []byte
}

type RegistrationResponse struct {
	Status          bool
	AssignedID      int
	TotalClients    uint32
	RevealThreshold uint32
}

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
}

type InitalReportingRequest struct {
	ShufflerID   int /// you should have some ways to ensure that the client does not lie about this
	InitialEntry ReportingEntry
}

type InitalReportingReply struct {
	Status          bool
	Shuffle_PubKeys []*ShufflePubKeys
}

type InitalReportingSecreteSharingRequest struct {
	ShufflerID    int /// you should have some ways to ensure that the client does not lie about this
	SecretePieces []*SecreteSharePoint
}

type InitalReportingSecreteSharingReply struct {
	Status bool
}

type ShufflePhaseAccquireLockRequest struct {
	ShufflerID int /// you should have some ways to ensure that the client does not lie about this
}

type ShufflePhaseAccquireLockReply struct {
	Status   bool
	Database Database
}

type ShufflePhasePerformShuffleResultRequest struct {
	ShufflerID int
	Database   Database
	ZKProofs   ZKRecords
}

type ShufflePhasePerformShuffleResultReply struct {
	Status bool
}

type RevealPhaseAcquireDatabaseRequest struct {
	ShufflerID int
}

type RevealPhaseAcquireDatabaseReply struct {
	Status   bool
	Database Database
}

type RevealPhaseReportRevealRequest struct {
	ShufflerID    int
	RevealRecords DecryptRecords
}

type RevealPhaseReportRevealReply struct {
	Status bool
}

type FaultTolerancePhaseAcquireDatabaseRequest struct {
	ShufflerID int
}

type FaultTolerancePhaseAcquireDatabaseReply struct {
	Status        bool
	FTNeeded      bool
	AbsentClients []int
	Database      Database
}

type FaultTolerancePhaseReportResultRequest struct {
	ShufflerID      int
	DecryptedPieces []SecreteShareDecrypt
}

type FaultTolerancePhaseReportResultReply struct {
	Status bool
}

type ClientStats struct {
	ClientID            int
	InitalReportingTime float64
	SecreteShareTime    float64
	ShuffleTime         float64
	RevealTime          float64
	FTTime              float64
	UploadBytes         int
	DownloadBytes       int
	Entry               []byte
}

type ReportStatsReply struct {
	Status bool
}
