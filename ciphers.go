// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import (
	"crypto/tls"

	"github.com/tmthrgd/tlsconfig/internal"
)

var (
	// CipherSuites is a preferred list of TLS cipher
	// suites with AES-GCM before ChaCha20-Poly1305.
	CipherSuites = cipherSuites(defaultSuites)

	// CipherSuitesChaCha20 is a preferred list of TLS
	// cipher suites with ChaCha20-Poly1305 before
	// AES-GCM.
	CipherSuitesChaCha20 = cipherSuites(chaCha20First)

	// CipherSuites3DES is equal to CipherSuites.
	//
	// Deprecated: This should no longer be used.
	CipherSuites3DES = CipherSuites
)

type cipherSuiteTypes int

const (
	defaultSuites cipherSuiteTypes = 0
	chaCha20First cipherSuiteTypes = 1 << iota
)

func cipherSuites(typ cipherSuiteTypes) []uint16 {
	var cipherSuites []uint16

	// TLS 1.3 cipher suites are not configurable in crypto/tls

	// SSL 3.0 - TLS 1.2 cipher suites

	if typ&chaCha20First == chaCha20First {
		// ECDHE+ChaCha20-Poly1305
		cipherSuites = append(cipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
	}

	cipherSuites = append(cipherSuites,
		// ECDHE+AES-GCM
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)

	if typ&chaCha20First != chaCha20First {
		// ECDHE+ChaCha20-Poly1305
		cipherSuites = append(cipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
	}

	return append(cipherSuites,
		// ECDHE+AES-CBC
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		// RSA+AES-GCM
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		// RSA+AES-CBC
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA)
}

// PrefersChaCha20 returns true iff a ChaCha20-Poly1305
// cipher suite is listed as the clients first preference.
func PrefersChaCha20(chi *tls.ClientHelloInfo) bool {
	id := chi.CipherSuites[0]
	return id == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 ||
		id == tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ||
		internal.IsTLS_CHACHA20_POLY1305_SHA256(id)
}

// Should3DES always returns false.
//
// Deprecated: This should no longer be used.
func Should3DES(*tls.ClientHelloInfo) bool { return false }
