package rulescore

import "math/big"

// sbox computes x^5 mod p (the Poseidon2 S-box for BN254).
func sbox(x *big.Int) *big.Int {
	p := BN254P
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, p)
	x4 := new(big.Int).Mul(x2, x2)
	x4.Mod(x4, p)
	r := new(big.Int).Mul(x4, x)
	r.Mod(r, p)
	return r
}

// matmulExternal4 applies the external (MDS) matrix multiply for t=4.
func matmulExternal4(s [4]*big.Int) [4]*big.Int {
	p := BN254P
	t0 := new(big.Int).Add(s[0], s[1])
	t0.Mod(t0, p)
	t1 := new(big.Int).Add(s[2], s[3])
	t1.Mod(t1, p)

	t2 := new(big.Int).Add(s[1], s[1])
	t2.Add(t2, t1)
	t2.Mod(t2, p)

	t3 := new(big.Int).Add(s[3], s[3])
	t3.Add(t3, t0)
	t3.Mod(t3, p)

	t4 := new(big.Int).Add(t1, t1)
	t4.Add(t4, t4)
	t4.Add(t4, t3)
	t4.Mod(t4, p)

	t5 := new(big.Int).Add(t0, t0)
	t5.Add(t5, t5)
	t5.Add(t5, t2)
	t5.Mod(t5, p)

	t6 := new(big.Int).Add(t3, t5)
	t6.Mod(t6, p)
	t7 := new(big.Int).Add(t2, t4)
	t7.Mod(t7, p)

	return [4]*big.Int{t6, t5, t7, t4}
}

// matmulInternal4 applies the internal matrix multiply for t=4: diag * x + sum(x).
func matmulInternal4(s [4]*big.Int) [4]*big.Int {
	p := BN254P
	total := new(big.Int).Add(s[0], s[1])
	total.Add(total, s[2])
	total.Add(total, s[3])
	total.Mod(total, p)

	var out [4]*big.Int
	for i := 0; i < 4; i++ {
		v := new(big.Int).Mul(MatDiag4M1[i], s[i])
		v.Add(v, total)
		v.Mod(v, p)
		out[i] = v
	}
	return out
}

// Permute runs the full Poseidon2 permutation for BN254, t=4.
func Permute(state [4]*big.Int) [4]*big.Int {
	p := BN254P
	s := state

	// Defensive copy
	for i := 0; i < 4; i++ {
		s[i] = new(big.Int).Set(s[i])
	}

	// Initial external matrix
	s = matmulExternal4(s)

	// 4 full beginning rounds
	for r := 0; r < 4; r++ {
		rc := RCFullBegin[r]
		for i := 0; i < 4; i++ {
			s[i].Add(s[i], rc[i])
			s[i].Mod(s[i], p)
		}
		for i := 0; i < 4; i++ {
			s[i] = sbox(s[i])
		}
		s = matmulExternal4(s)
	}

	// 56 partial rounds
	for r := 0; r < 56; r++ {
		s[0].Add(s[0], RCPartial[r])
		s[0].Mod(s[0], p)
		s[0] = sbox(s[0])
		s = matmulInternal4(s)
	}

	// 4 full ending rounds
	for r := 0; r < 4; r++ {
		rc := RCFullEnd[r]
		for i := 0; i < 4; i++ {
			s[i].Add(s[i], rc[i])
			s[i].Mod(s[i], p)
		}
		for i := 0; i < 4; i++ {
			s[i] = sbox(s[i])
		}
		s = matmulExternal4(s)
	}

	return s
}

// Sponge implements the Poseidon2 sponge construction with rate=3, capacity=1, t=4.
type Sponge struct {
	state     [4]*big.Int
	cache     [3]*big.Int
	cacheSize int
	mode      int // 0 = absorb, 1 = squeeze
}

const (
	spongeRate    = 3
	spongeT       = 4
	modeAbsorb    = 0
	modeSqueeze   = 1
)

// NewSponge creates a new Poseidon2 sponge with the given domain IV.
func NewSponge(domainIV *big.Int) *Sponge {
	s := &Sponge{mode: modeAbsorb}
	for i := 0; i < 4; i++ {
		s.state[i] = new(big.Int)
	}
	s.state[3].Set(domainIV)
	for i := 0; i < spongeRate; i++ {
		s.cache[i] = new(big.Int)
	}
	return s
}

func (s *Sponge) performDuplex() [3]*big.Int {
	p := BN254P
	// Zero-pad cache
	for i := s.cacheSize; i < spongeRate; i++ {
		s.cache[i] = new(big.Int)
	}
	// Add cache into sponge state
	for i := 0; i < spongeRate; i++ {
		s.state[i].Add(s.state[i], s.cache[i])
		s.state[i].Mod(s.state[i], p)
	}
	s.state = Permute(s.state)
	var out [3]*big.Int
	for i := 0; i < spongeRate; i++ {
		out[i] = new(big.Int).Set(s.state[i])
	}
	return out
}

// Absorb adds a field element to the sponge.
func (s *Sponge) Absorb(value *big.Int) {
	if s.mode == modeAbsorb && s.cacheSize == spongeRate {
		s.performDuplex()
		s.cache[0] = new(big.Int).Set(value)
		s.cacheSize = 1
	} else if s.mode == modeAbsorb && s.cacheSize < spongeRate {
		s.cache[s.cacheSize] = new(big.Int).Set(value)
		s.cacheSize++
	} else if s.mode == modeSqueeze {
		s.cache[0] = new(big.Int).Set(value)
		s.cacheSize = 1
		s.mode = modeAbsorb
	}
}

// Squeeze extracts a field element from the sponge.
func (s *Sponge) Squeeze() *big.Int {
	if s.mode == modeSqueeze && s.cacheSize == 0 {
		s.mode = modeAbsorb
		s.cacheSize = 0
	}

	if s.mode == modeAbsorb {
		newOutput := s.performDuplex()
		s.mode = modeSqueeze
		for i := 0; i < spongeRate; i++ {
			s.cache[i] = newOutput[i]
		}
		s.cacheSize = spongeRate
	}

	result := new(big.Int).Set(s.cache[0])
	for i := 1; i < s.cacheSize; i++ {
		s.cache[i-1] = s.cache[i]
	}
	s.cacheSize--
	s.cache[s.cacheSize] = new(big.Int)
	return result
}

// Hash computes a Poseidon2 hash over a list of field elements (fixed-length).
func Hash(inputs []*big.Int) *big.Int {
	outLen := 1
	iv := new(big.Int).Lsh(big.NewInt(int64(len(inputs))), 64)
	iv.Add(iv, big.NewInt(int64(outLen-1)))

	sponge := NewSponge(iv)
	for _, v := range inputs {
		sponge.Absorb(v)
	}
	return sponge.Squeeze()
}

// BytesToFieldElements converts bytes to BN254 field elements (31-byte chunks, big-endian).
func BytesToFieldElements(data []byte) []*big.Int {
	if len(data) == 0 {
		return []*big.Int{new(big.Int)}
	}

	var elements []*big.Int
	chunkSize := 31
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		value := new(big.Int).SetBytes(chunk) // big-endian
		value.Mod(value, BN254P)
		elements = append(elements, value)
	}
	return elements
}

// Poseidon2Bytes computes a Poseidon2 hash over arbitrary bytes,
// matching the TS/Python commitment.ts/commitment.py sponge pattern.
func Poseidon2Bytes(data []byte) string {
	elements := BytesToFieldElements(data)
	p := BN254P

	state := new(big.Int)
	for i := 0; i < len(elements); i += 2 {
		left := elements[i]
		right := new(big.Int)
		if i+1 < len(elements) {
			right.Set(elements[i+1])
		}
		sum := new(big.Int).Add(state, left)
		sum.Mod(sum, p)
		state = Hash([]*big.Int{sum, right})
	}

	hex := state.Text(16)
	// Pad to 64 hex chars
	for len(hex) < 64 {
		hex = "0" + hex
	}
	return "poseidon2:" + hex
}
