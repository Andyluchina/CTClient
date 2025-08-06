package elgamal

import (
	"CTLogchecker/ClientApp/zklib"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/nistec"
)

const web_cert_len = 2048
const apply_compressions = true

const ORDER_OF_P256 = "1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111110111100111001101111101010101101101001110001011110011110100001001111001110111001110010101100001011111100011000110010010101010001"
const cert_len = 32

func ORDER_OF_P256_big() *big.Int {
	order, _ := new(big.Int).SetString(ORDER_OF_P256, 2)
	return order
}

func ECDH_bytes(point []byte, scalar []byte) ([]byte, error) {
	pub_point, err := nistec.NewP256Point().SetBytes(point)
	if err != nil {
		return nil, errors.New("the provided point is not a point on the curve")
	}

	_, err = pub_point.ScalarMult(pub_point, scalar)
	if err != nil {
		panic(err)
		// return nil, errors.New("the provided scalar is not a valid scalar")
	}
	if apply_compressions {
		return pub_point.BytesCompressed(), nil
	} else {
		return pub_point.Bytes(), nil
	}
}

func ECDH_bytes_P256_arbitrary_scalar_len(point []byte, scalar []byte) ([]byte, error) {
	pub_point, err := nistec.NewP256Point().SetBytes(point)
	if err != nil {
		return nil, errors.New("the provided point is not a point on the curve")
	}

	scalar = PadTo32Bytes(scalar)
	_, err = pub_point.ScalarMult(pub_point, scalar)
	if err != nil {
		panic(err)
		// return nil, errors.New("the provided scalar is not a valid scalar")
	}
	if apply_compressions {
		return pub_point.BytesCompressed(), nil
	} else {
		return pub_point.Bytes(), nil
	}
}

func ReturnNegative(point []byte) ([]byte, error) {
	// point_p, err := nistec.NewP256Point().SetBytes(point)
	point_p, err := nistec.NewP256Point().SetBytes(point)

	if err != nil {
		return nil, errors.New("point is not a point on the curve")
	}
	point_p.Negate(point_p)
	if apply_compressions {
		return point_p.BytesCompressed(), nil
	} else {
		return point_p.Bytes(), nil
	}
}

func ReturnZeroPoint() []byte {
	point_p := nistec.NewP256Point()
	if apply_compressions {
		return point_p.BytesCompressed()
	} else {
		return point_p.Bytes()
	}
}

func Encrypt(shared_secret []byte, msg []byte) ([]byte, error) {
	/// assuming curve here, TODO Add the curve type
	shared_secret_point, err := nistec.NewP256Point().SetBytes(shared_secret)
	if err != nil {
		return nil, errors.New("shared secrete is not a point on the curve")
	}
	msg_point, err := nistec.NewP256Point().SetBytes(msg)
	if err != nil {
		return nil, errors.New("msg is not a point on the curve")
	}
	res := nistec.NewP256Point()

	res.Add(shared_secret_point, msg_point)
	if apply_compressions {
		return res.BytesCompressed(), nil
	} else {
		return res.Bytes(), nil
	}
}

func Decrypt(shared_secret []byte, cyphertext []byte) ([]byte, error) {
	/// assuming curve here, TODO Add the curve type
	shared_secret_point, err := nistec.NewP256Point().SetBytes(shared_secret)
	if err != nil {
		return nil, errors.New("shared secrete is not a point on the curve")
	}
	cyphertext_point, err := nistec.NewP256Point().SetBytes(cyphertext)
	if err != nil {
		return nil, errors.New("msg is not a point on the curve")
	}

	shared_secret_point.Negate(shared_secret_point)
	res := nistec.NewP256Point()

	res.Add(cyphertext_point, shared_secret_point)
	if apply_compressions {
		return res.BytesCompressed(), nil
	} else {
		return res.Bytes(), nil
	}
}

func Generate_certificate() []byte {
	/// generate a random certificate, splt it into 9 pieces, first byte is padding, last 2 bytes are sha256 hashes
	/// here we are just generating the certificate
	// 2048 bits is 256 bytes, generate one certificate randomly
	slice := make([]byte, 32)

	// Read fills slice with random data
	_, err := rand.Read(slice)
	if err != nil {
		fmt.Println("Error generating random bits for certificate:", err)
		panic(err)
	}

	return slice
}

func Generate_Random_Dice_seed(curve ecdh.Curve) []byte {
	new_p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return new_p.Bytes()
}

func Generate_Random_Dice_point(curve ecdh.Curve) []byte {
	new_p, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	res, _ := Convert_Compression(new_p.PublicKey().Bytes())
	return res
}

func Convert_seed_To_point(seed []byte, curve ecdh.Curve) ([]byte, error) {
	new_p, err := curve.NewPrivateKey(seed)
	if err != nil {
		return nil, errors.New("seed not valid")
	}
	res, _ := Convert_Compression(new_p.PublicKey().Bytes())
	return res, nil
}

func Convert_Compression(uncompressed_point []byte) ([]byte, error) {
	if apply_compressions {
		// compress the point
		compressed_point, err := nistec.NewP256Point().SetBytes(uncompressed_point)
		if err != nil {
			return nil, errors.New("point not valid")
		}
		return compressed_point.BytesCompressed(), nil
	} else {
		return uncompressed_point, nil
	}
}

// padTo32Bytes takes a byte slice and returns a new slice that is exactly 32 bytes long.
// If the input slice is longer than 32 bytes, it panics.
// If the input slice is 32 bytes or shorter, it prepends the slice with zero bytes to make it 32 bytes long.
func PadTo32Bytes(data []byte) []byte {
	const targetLength = 32
	dataLength := len(data)
	// myStr := strconv.Itoa(dataLength)
	if dataLength > targetLength {
		// fmt.Println("Data length is greater than 32 bytes")
		i := zklib.SetBigIntWithBytes(data)
		i.Mod(i, ORDER_OF_P256_big())
		data = i.Bytes()
		dataLength = len(data)
	}

	// Calculate how many bytes to prepend.
	prependLength := targetLength - dataLength

	if prependLength == 0 {
		return data
	}
	// Create a slice of the required length filled with zero bytes.
	prependSlice := make([]byte, prependLength)

	// Append the original data to the prependSlice. This will not alter the original data slice.
	// Use copy if you need to put it in the beginning of the slice (prepend).
	result := append(prependSlice, data...)
	// fmt.Println("Padded length is: ", prependLength)
	// fmt.Println(result)

	return result
}

func ReturnInfinityPoint() []byte {
	/// assuming curve here, TODO Add the curve type
	// base_point := nistec.NewP256Point()
	base_point := nistec.NewP256Point()

	if apply_compressions {
		return base_point.BytesCompressed()
	} else {
		return base_point.Bytes()
	}
}
