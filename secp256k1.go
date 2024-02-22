package secp256k1

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	secp_dcrec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	secp_eth "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

/*
SignRFC6979 generates a deterministic ECDSA signature according to RFC 6979 and BIP 62.
*/
func SignRFC6979(sk *ecdsa.PrivateKey, hash common.Hash) (*big.Int, *big.Int, error) {
	curve := secp_dcrec.S256()
	// 使用RFC 6979生成随机数nonce, 需要传入私钥sk, message的hash来生成, 确保每一次签名r,s都一样
	// 即对于同一sk,hash产生的nonce永远相同（ETH\BTC约定的）
	// 如需不同的签名r,s可以调用以下方式获取
	// r, s, err := ecdsa.Sign(rand.Reader, skECDSA, crypto.Keccak256([]byte("hello")))
	nonce := secp_dcrec.NonceRFC6979(sk.D.Bytes(), hash.Bytes(), nil, nil, 0).Bytes()
	// 有了随机数nonce, 开始计算r
	// r就是nonce*G在曲线上那个点的x坐标 (有限域N内,即mod N)
	r, _ := curve.ScalarBaseMult(nonce[:]) // r = nonce * G 点的x坐标
	r.Mod(r, curve.N)                      // r = r mod N
	if r.Sign() == 0 {                     // 验证r
		return nil, nil, errors.New("calculated R is zero")
	}

	// s就是私钥乘以r加上hash再除以nonce, 即 (sk*r + hash(m))/nonce (有限域N内,即mod N)
	inv := new(big.Int).ModInverse(new(big.Int).SetBytes(nonce[:]), curve.N) // inv = nonce^-1 mod N
	s := new(big.Int).Mul(sk.D, r)                                           // s = sk * r
	s.Add(s, hash.Big())                                                     // s = s + hash(m)
	s.Mul(s, inv)                                                            // s = s * nonce^-1
	s.Mod(s, curve.N)                                                        // s = s mod N

	// if s.Cmp(halfN) == 1 {												 // if s > N/2, then s = N - s
	// 	s.Sub(curve.N, s)
	// }
	var s1 secp_dcrec.ModNScalar
	s1.SetByteSlice(s.Bytes())
	if s1.IsOverHalfOrder() {
		s.Sub(curve.N, s)
	}

	if s.Sign() == 0 { // 验证s
		return nil, nil, errors.New("calculated S is zero")
	}
	return r, s, nil
}

// 验签过程：
// 设公钥PK = sk*G, 证明 (hash(m)*G)/s + r*PK/s = nonce*G
//		(hash(m)*G)/s + r*PK/s
// =>	(hash(m)*G)/s + r*sk*G/s
// =>	(hash(m) + r*sk) * G /s
// 由于 s = (sk*r + hash(m))/nonce
// => 	(hash(m) + r*sk) * G *nonce / (sk*r + hash(m))
// =>	G*nonce

func GetPublicKey(sk *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	curve := secp_dcrec.S256()
	x, y := curve.ScalarBaseMult(sk.D.Bytes())
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("internal error")
	}
	pub := ecdsa.PublicKey{
		Curve: secp_eth.S256(), // 用ETH的curve
		X:     x,
		Y:     y,
	}
	return &pub, nil
}

// 下面使用go的big.Int实现ScalarMult算法
// Point multiplication: Double-and-add
// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

type Fq struct {
	Z, P *big.Int
}

func newFq(x int64) *Fq {
	curve := secp_eth.S256()
	return &Fq{
		Z: new(big.Int).Mod(big.NewInt(x), curve.P),
		P: curve.P,
	}
}

func (f *Fq) Set(x *big.Int) *Fq {
	curve := secp_eth.S256()
	f.Z = new(big.Int).Set(x)
	f.P = curve.P
	return f
}

func (f *Fq) Equal(x *Fq) bool {
	return f.P.Cmp(x.P) == 0 && f.Z.Cmp(x.Z) == 0
}

func (f *Fq) Neg() *Fq {
	f.Z.Neg(f.Z)
	return f
}

func (f *Fq) Mul(x *Fq) *Fq {
	if f.P.Cmp(x.P) == 0 {
		f.Z.Mul(f.Z, x.Z)
		f.Z.Mod(f.Z, f.P)
		return f
	}
	return nil
}

func (f *Fq) Div(x *Fq) *Fq {
	if f.P.Cmp(x.P) == 0 {
		inv := new(big.Int).ModInverse(x.Z, f.P)
		f.Z.Mul(f.Z, inv)
		f.Z.Mod(f.Z, f.P)
		return f
	}
	return nil
}

func (f *Fq) Add(x *Fq) *Fq {
	if f.P.Cmp(x.P) == 0 {
		f.Z.Add(f.Z, x.Z)
		f.Z.Mod(f.Z, f.P)
		return f
	}
	return nil
}

func (f *Fq) Sub(x *Fq) *Fq {
	if f.P.Cmp(x.P) == 0 {
		f.Z.Sub(f.Z, x.Z)
		f.Z.Mod(f.Z, f.P)
		return f
	}
	return nil
}

func (f *Fq) String() string {
	return f.Z.Text(16)
}

type Point struct {
	X, Y *Fq
}

func (p *Point) Set(x, y *big.Int) *Point {
	if x.Cmp(big.NewInt(0)) != 0 && y.Cmp(big.NewInt(0)) != 0 {
		c := newFq(7)
		px := new(big.Int).Exp(x, big.NewInt(3), c.P)
		py := new(big.Int).Exp(y, big.NewInt(2), c.P)
		if py.Cmp(px.Add(px, c.Z)) != 0 {
			return nil
		}
	}
	return &Point{
		X: new(Fq).Set(x),
		Y: new(Fq).Set(y),
	}
}

func (p *Point) String() string {
	return "Point(" + p.X.String() + ", " + p.Y.String() + ")"
}

func (p *Point) Add(x *Point) *Point {
	if p.X.Equal(newFq(0)) && p.Y.Equal(newFq(0)) {
		return x
	}
	if x.X.Equal(newFq(0)) && x.Y.Equal(newFq(0)) {
		return p
	}
	if p.X.Equal(x.X) {
		y_ := new(Fq).Set(x.Y.Z)
		y_.Neg()
		if p.Y.Equal(y_) {
			return new(Point).Set(big.NewInt(0), big.NewInt(0))
		}
	}
	x1 := p.X
	x2 := x.X
	y1 := p.Y
	y2 := x.Y
	var s *Fq
	if p.Y.Equal(x.Y) {
		a := new(Fq).Set(x1.Z) // s = (x1 * x1 + x1 * x1 + x1 * x1 + A) / (y1 + y1)
		a.Mul(a)
		b := new(Fq).Set(a.Z)
		b.Add(a)
		b.Add(a)
		b.Add(newFq(0))
		c := new(Fq).Set(y1.Z)
		c.Add(c)
		s = b.Div(c)
	} else {
		a := new(Fq).Set(y2.Z) // s = (y2 - y1) / (x2 - x1)
		a.Sub(y1)
		b := new(Fq).Set(x2.Z)
		b.Sub(x1)
		s = a.Div(b)
	}
	x3 := new(Fq).Set(s.Z) // x3 = s * s - x1 - x2
	x3.Mul(x3)
	x3.Sub(x1)
	x3.Sub(x2)
	y3 := new(Fq).Set(x1.Z) // y3 = s * (x1 - x3) - y1
	y3.Sub(x3)
	y3.Mul(s)
	y3.Sub(y1)
	return &Point{
		X: x3,
		Y: y3,
	}
}

func ScalarMult(sk *ecdsa.PrivateKey, Gx, Gy *big.Int) (*big.Int, *big.Int, error) {
	r := new(Point).Set(big.NewInt(0), big.NewInt(0))
	n := new(big.Int).Set(sk.D)
	addend := new(Point).Set(Gx, Gy)
	for n.Cmp(big.NewInt(0)) > 0 {
		b := new(big.Int).And(n, big.NewInt(1)) // b = n & 1
		if b.Cmp(big.NewInt(1)) == 0 {
			r = r.Add(addend) // r += addend
		}
		addend = addend.Add(addend) // addend = addend + addend
		n.Rsh(n, 1)                 // n = n >> 1
	}
	return r.X.Z, r.Y.Z, nil
}
