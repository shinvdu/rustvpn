// Deterministic GoVPN 5.7 oracle vector generator for the Rust port.
//
// This program is test tooling only.  It imports the unmodified Go
// implementation via GOPATH and emits JSON vectors consumed by
// cargo tests under rust/testdata/go_vectors.json.
//
// Run from the repository root:
//
//	GO111MODULE=off GOPATH=$(pwd) go run rust/tools/gen-vectors/main.go \
//	    > rust/testdata/go_vectors.json
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agl/ed25519/extra25519"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/xtea"

	"cypherpunks.ru/govpn/aont"
	"cypherpunks.ru/govpn/cnw"

	"cypherpunks.ru/govpn"
)

type xteaVec struct {
	Key    string `json:"key"`
	Plain  string `json:"plain"`
	Cipher string `json:"cipher"`
}

type streamVec struct {
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

type polyVec struct {
	Key string `json:"key"`
	Msg string `json:"msg"`
	Tag string `json:"tag"`
}

type hashVec struct {
	Input  string `json:"input"`
	Digest string `json:"digest"`
}

type cnwVec struct {
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`
	Input  string `json:"input"`
	Chaff  string `json:"chaff"`
	Winnow string `json:"winnow"`
}

type aontVec struct {
	R       string `json:"r"`
	Input   string `json:"input"`
	Encoded string `json:"encoded"`
}

type verifierVec struct {
	Password  string `json:"password"`
	Id        string `json:"id"`
	M         int    `json:"m"`
	T         int    `json:"t"`
	P         int    `json:"p"`
	Seed      string `json:"seed"`
	Public    string `json:"public"`
	ShortForm string `json:"short_form"`
	LongForm  string `json:"long_form"`
}

type elligatorFlagVec struct {
	Private string `json:"private"`
	OK      bool   `json:"ok"`
	Public  string `json:"public,omitempty"`
	Repr    string `json:"repr,omitempty"`
}

type elligatorVec struct {
	Private string `json:"private"`
	Public  string `json:"public"`
	Repr    string `json:"repr"`
}

type handshakeVec struct {
	Mode     string   `json:"mode"`
	Seed     uint64   `json:"seed"`
	Mtu      int      `json:"mtu"`
	Password string   `json:"password"`
	Id       string   `json:"id"`
	M        int      `json:"m"`
	T        int      `json:"t"`
	P        int      `json:"p"`
	SeedPriv string   `json:"seed_priv"`
	Public   string   `json:"public"`
	Messages []string `json:"messages"`
	Key      string   `json:"key"`
	RandPos  []int    `json:"rand_pos"`
}

type transportVec struct {
	Mode    string `json:"mode"`
	Side    string `json:"side"`
	Mtu     int    `json:"mtu"`
	Key     string `json:"key"`
	Payload string `json:"payload"`
	Wire    string `json:"wire"`
	Serial  uint64 `json:"serial"`
}

type vectors struct {
	Xtea           []xteaVec          `json:"xtea"`
	Salsa20        []streamVec        `json:"salsa20"`
	XSalsa20       []streamVec        `json:"xsalsa20"`
	Poly1305       []polyVec          `json:"poly1305"`
	Blake2b256     []hashVec          `json:"blake2b256"`
	Cnw            []cnwVec           `json:"cnw"`
	Aont           []aontVec          `json:"aont"`
	Verifier       []verifierVec      `json:"verifier"`
	Elligator      []elligatorVec     `json:"elligator"`
	ElligatorFlags []elligatorFlagVec `json:"elligator_flags"`
	Handshake      []handshakeVec     `json:"handshake"`
	Transport      []transportVec     `json:"transport"`
}

type detRand struct {
	data []byte
	pos  int
}

func (d *detRand) Read(p []byte) (int, error) {
	if d.pos+len(p) > len(d.data) {
		return 0, io.EOF
	}
	copy(p, d.data[d.pos:])
	d.pos += len(p)
	return len(p), nil
}

func deterministicRand(seed uint64) io.Reader {
	data := make([]byte, 4<<20)
	var block [8]byte
	for i := 0; i*32 < len(data); i++ {
		binary.BigEndian.PutUint64(block[:], seed)
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], uint64(i))
		sum := sha256.Sum256(append(block[:], ctr[:]...))
		copy(data[i*32:], sum[:])
	}
	return &detRand{data: data}
}

type capture struct {
	buf []byte
}

func (c *capture) Write(p []byte) (int, error) {
	c.buf = append(c.buf[:0], p...)
	return len(p), nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func main() {
	out := vectors{}

	// XTEA.
	var xkey [16]byte
	var xplain [8]byte
	for i := range xkey {
		xkey[i] = byte(i * 7)
	}
	for i := range xplain {
		xplain[i] = byte(0xa0 + i)
	}
	ciph, err := xtea.NewCipher(xkey[:])
	must(err)
	var xcipher [8]byte
	ciph.Encrypt(xcipher[:], xplain[:])
	out.Xtea = append(out.Xtea, xteaVec{hx(xkey[:]), hx(xplain[:]), hx(xcipher[:])})

	// Salsa20 / XSalsa20.
	var skey [32]byte
	for i := range skey {
		skey[i] = byte(i + 1)
	}
	for _, n := range []int{8, 24} {
		var nonce [24]byte
		for i := 0; i < n; i++ {
			nonce[i] = byte(0x30 + i)
		}
		in := make([]byte, 128)
		for i := range in {
			in[i] = byte(i * 3)
		}
		data := make([]byte, len(in))
		salsa20.XORKeyStream(data, in, nonce[:n], &skey)
		v := streamVec{hx(skey[:]), hx(nonce[:n]), hx(in), hx(data)}
		if n == 8 {
			out.Salsa20 = append(out.Salsa20, v)
		} else {
			out.XSalsa20 = append(out.XSalsa20, v)
		}
	}

	// Poly1305.
	var pkey [32]byte
	for i := range pkey {
		pkey[i] = byte(0x40 + i)
	}
	for _, n := range []int{1, 16, 17, 100} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i ^ 0x5a)
		}
		var tag [16]byte
		poly1305.Sum(&tag, msg, &pkey)
		out.Poly1305 = append(out.Poly1305, polyVec{hx(pkey[:]), hx(msg), hx(tag[:])})
	}

	// BLAKE2b-256.
	for _, n := range []int{0, 1, 16, 100, 1000} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 5)
		}
		sum := blake2b.Sum256(msg)
		out.Blake2b256 = append(out.Blake2b256, hashVec{hx(msg), hx(sum[:])})
	}

	// cnw + AONT.
	var ckey [32]byte
	for i := range ckey {
		ckey[i] = byte(0x11 * (i + 1))
	}
	var cnonce [8]byte
	for i := range cnonce {
		cnonce[i] = byte(0x80 + i)
	}
	for _, n := range []int{1, 16, 32} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i*9 + 3)
		}
		chaffed := cnw.Chaff(&ckey, cnonce[:], in)
		winnowed, err := cnw.Winnow(&ckey, cnonce[:], chaffed)
		must(err)
		out.Cnw = append(out.Cnw, cnwVec{
			hx(ckey[:]), hx(cnonce[:]), hx(in), hx(chaffed), hx(winnowed),
		})
	}
	var ar [16]byte
	for i := range ar {
		ar[i] = byte(i + 0x20)
	}
	for _, n := range []int{0, 1, 100, 1500} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i * 11)
		}
		enc, err := aont.Encode(&ar, in)
		must(err)
		out.Aont = append(out.Aont, aontVec{hx(ar[:]), hx(in), hx(enc)})
	}

	// Verifier.
	var vid [govpn.IDSize]byte
	for i := range vid {
		vid[i] = byte(i)
	}
	pid := govpn.PeerId(vid)
	v := govpn.VerifierNew(1024, 4, 1, &pid)
	priv := v.PasswordApply("testpass")
	seedBytes := priv[:32]
	seed := seedBytes
	out.Verifier = append(out.Verifier, verifierVec{
		Password:  "testpass",
		Id:        hx(vid[:]),
		M:         1024,
		T:         4,
		P:         1,
		Seed:      hx(seed),
		Public:    hx(v.Pub[:]),
		ShortForm: v.ShortForm(),
		LongForm:  v.LongForm(),
	})

	// Elligator/extra25519 vectors for the future handshake port.
	dr := deterministicRand(7000)
	for i := 0; i < 8; i++ {
		var epriv [32]byte
		_, _ = io.ReadFull(dr, epriv[:])
		var epub, erepr [32]byte
		for !extra25519.ScalarBaseMult(&epub, &erepr, &epriv) {
			_, _ = io.ReadFull(dr, epriv[:])
		}
		out.Elligator = append(out.Elligator, elligatorVec{
			hx(epriv[:]), hx(epub[:]), hx(erepr[:]),
		})
	}

	// Representability classification for arbitrary private candidates.
	{
		dr := deterministicRand(3000)
		for i := 0; i < 300; i++ {
			var priv [32]byte
			_, _ = io.ReadFull(dr, priv[:])
			var pub, repr [32]byte
			ok := extra25519.ScalarBaseMult(&pub, &repr, &priv)
			v := elligatorFlagVec{Private: hx(priv[:]), OK: ok}
			if ok {
				v.Public = hx(pub[:])
				v.Repr = hx(repr[:])
			}
			out.ElligatorFlags = append(out.ElligatorFlags, v)
		}
	}

	// Handshake vectors: deterministic Rand stream, messages and master key.
	for idx, mode := range []string{"plain", "noise", "encless"} {
		seed := uint64(2000 + idx)
		govpn.Rand = deterministicRand(seed)
		dr := govpn.Rand.(*detRand)
		randPos := []int{}
		noise := mode != "plain"
		encless := mode == "encless"
		if encless {
			noise = true
		}
		clientConf := &govpn.PeerConf{
			Id: v.Id, MTU: govpn.MTUDefault, Timeout: 60 * time.Second,
			Noise: noise, Encless: encless, Verifier: v, DSAPriv: priv,
		}
		serverConf := &govpn.PeerConf{
			Id: v.Id, MTU: govpn.MTUDefault, Timeout: 60 * time.Second,
			Noise: noise, Encless: encless, Verifier: v,
		}
		clientConn := &capture{}
		serverConn := &capture{}
		hsS := govpn.NewHandshake("server", serverConn, serverConf)
		hsC := govpn.HandshakeStart("client", clientConn, clientConf)
		msg1 := append([]byte(nil), clientConn.buf...)
		randPos = append(randPos, dr.pos)
		hsS.Server(msg1)
		randPos = append(randPos, dr.pos)
		msg2 := append([]byte(nil), serverConn.buf...)
		hsC.Client(msg2)
		randPos = append(randPos, dr.pos)
		msg3 := append([]byte(nil), clientConn.buf...)
		serverPeer := hsS.Server(msg3)
		randPos = append(randPos, dr.pos)
		msg4 := append([]byte(nil), serverConn.buf...)
		clientPeer := hsC.Client(msg4)
		randPos = append(randPos, dr.pos)
		if serverPeer == nil || clientPeer == nil {
			fmt.Fprintln(os.Stderr, "handshake vectors failed for", mode)
			os.Exit(1)
		}
		key := *clientPeer.Key
		if !bytes.Equal(key[:], serverPeer.Key[:]) {
			fmt.Fprintln(os.Stderr, "handshake keys differ")
			os.Exit(1)
		}
		out.Handshake = append(out.Handshake, handshakeVec{
			Mode: mode, Seed: seed, Mtu: govpn.MTUDefault,
			Password: "testpass", Id: hx(vid[:]), M: 1024, T: 4, P: 1,
			SeedPriv: hx(seedBytes), Public: hx(v.Pub[:]),
			Messages: []string{hx(msg1), hx(msg2), hx(msg3), hx(msg4)},
			Key:      hx(key[:]),
			RandPos:  randPos,
		})
	}

	// Transport vectors: derive a deterministic session via the real
	// handshake, then capture the first packet in both directions.
	for idx, mode := range []string{"plain", "noise", "encless"} {
		govpn.Rand = deterministicRand(uint64(1000 + idx))
		noise := mode != "plain"
		encless := mode == "encless"
		if encless {
			noise = true
		}
		clientConf := &govpn.PeerConf{
			Id:       v.Id,
			MTU:      govpn.MTUDefault,
			Timeout:  60 * time.Second,
			Noise:    noise,
			Encless:  encless,
			Verifier: v,
			DSAPriv:  priv,
		}
		serverConf := &govpn.PeerConf{
			Id:       v.Id,
			MTU:      govpn.MTUDefault,
			Timeout:  60 * time.Second,
			Noise:    noise,
			Encless:  encless,
			Verifier: v,
		}
		clientConn := &capture{}
		serverConn := &capture{}
		hsS := govpn.NewHandshake("server", serverConn, serverConf)
		hsC := govpn.HandshakeStart("client", clientConn, clientConf)
		hsS.Server(clientConn.buf)
		hsC.Client(serverConn.buf)
		serverPeer := hsS.Server(clientConn.buf)
		clientPeer := hsC.Client(serverConn.buf)
		if serverPeer == nil || clientPeer == nil {
			fmt.Fprintln(os.Stderr, "handshake failed for mode", mode)
			os.Exit(1)
		}
		clientKey := *clientPeer.Key
		serverKey := *serverPeer.Key
		if !bytes.Equal(clientKey[:], serverKey[:]) {
			fmt.Fprintln(os.Stderr, "client/server keys differ")
			os.Exit(1)
		}
		clientConn.buf = nil
		serverConn.buf = nil
		payload := make([]byte, 100)
		for i := range payload {
			payload[i] = byte(i*3 + 1)
		}

		clientPeer.EthProcess(payload)
		clientWire := append([]byte(nil), clientConn.buf...)
		serverPeer.EthProcess(payload)
		serverWire := append([]byte(nil), serverConn.buf...)
		// PktProcess decrypts the nonce in place; verify copies so the
		// captured wire bytes stay pristine for the vectors.
		verifyClient := append([]byte(nil), clientWire...)
		verifyServer := append([]byte(nil), serverWire...)
		if !serverPeer.PktProcess(verifyClient, io.Discard, true) {
			fmt.Fprintln(os.Stderr, "Go failed to decode client wire", mode)
			os.Exit(1)
		}
		if !clientPeer.PktProcess(verifyServer, io.Discard, true) {
			fmt.Fprintln(os.Stderr, "Go failed to decode server wire", mode)
			os.Exit(1)
		}
		out.Transport = append(out.Transport,
			transportVec{
				Mode: mode, Side: "client", Mtu: govpn.MTUDefault,
				Key: hx(clientKey[:]), Payload: hx(payload),
				Wire: hx(clientWire), Serial: 3,
			},
			transportVec{
				Mode: mode, Side: "server", Mtu: govpn.MTUDefault,
				Key: hx(serverKey[:]), Payload: hx(payload),
				Wire: hx(serverWire), Serial: 2,
			},
		)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
