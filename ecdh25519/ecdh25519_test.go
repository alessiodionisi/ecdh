package ecdh25519_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/adnsio/ecdh/ecdh25519"
)

// test vectors from: https://www.ietf.org/rfc/rfc7748.html#section-6.1

func TestGenerateKeyPair(t *testing.T) {
	type args struct {
		rand io.Reader
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "with crypto rand",
			args: args{
				rand: rand.Reader,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ecdh25519.GenerateKeyPair(tt.args.rand)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGenerateSharedSecret(t *testing.T) {
	type args struct {
		privateKey ecdh25519.PrivateKey
		publicKey  ecdh25519.PublicKey
	}

	alicePrivateKey, err := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}

	alicePublicKey, err := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	if err != nil {
		t.Fatal(err)
	}

	bobPrivateKey, err := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	if err != nil {
		t.Fatal(err)
	}

	bobPublicKey, err := hex.DecodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	if err != nil {
		t.Fatal(err)
	}

	sharedSecret, err := hex.DecodeString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "with alice secret and bob public",
			args: args{
				privateKey: alicePrivateKey,
				publicKey:  bobPublicKey,
			},
			want: sharedSecret,
		},
		{
			name: "with bob secret and alice public",
			args: args{
				privateKey: bobPrivateKey,
				publicKey:  alicePublicKey,
			},
			want: sharedSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecdh25519.GenerateSharedSecret(tt.args.privateKey, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSharedSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateSharedSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivateKey_PublicKey(t *testing.T) {
	alicePrivateKey, err := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	if err != nil {
		t.Fatal(err)
	}

	alicePublicKey, err := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	if err != nil {
		t.Fatal(err)
	}

	bobPrivateKey, err := hex.DecodeString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	if err != nil {
		t.Fatal(err)
	}

	bobPublicKey, err := hex.DecodeString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		p       ecdh25519.PrivateKey
		want    ecdh25519.PublicKey
		wantErr bool
	}{
		{
			name: "alice public",
			p:    alicePrivateKey,
			want: alicePublicKey,
		},
		{
			name: "bob public",
			p:    bobPrivateKey,
			want: bobPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.PublicKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKey.PublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PrivateKey.PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

var benchmarkSink byte

func BenchmarkGenerateKeyPair(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		publicKey, privateKey, err := ecdh25519.GenerateKeyPair(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		benchmarkSink ^= publicKey[0]
		benchmarkSink ^= privateKey[0]
	}
}

func ExampleGenerateKeyPair() {
	alicePublicKey, alicePrivateKey, err := ecdh25519.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}

	bobPublicKey, bobPrivateKey, err := ecdh25519.GenerateKeyPair(rand.Reader)
	if err != nil {
		panic(err)
	}

	aliceSharedSecret, err := ecdh25519.GenerateSharedSecret(alicePrivateKey, bobPublicKey)
	if err != nil {
		panic(err)
	}

	bobSharedSecret, err := ecdh25519.GenerateSharedSecret(bobPrivateKey, alicePublicKey)
	if err != nil {
		panic(err)
	}

	if bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		fmt.Printf("shared secrets are equal")
	}

	// Output: shared secrets are equal
}
