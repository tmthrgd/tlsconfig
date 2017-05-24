// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import (
	"crypto/tls"

	"github.com/tmthrgd/tlsconfig/internal/tls-tris"
)

var (
	// CipherSuites is a preferred list of TLS cipher
	// suites with AES-GCM before ChaCha20-Poly1305.
	CipherSuites = cipherSuites(defaultSuites)

	// CipherSuitesChaCha20 is a preferred list of TLS
	// cipher suites with ChaCha20-Poly1305 before
	// AES-GCM.
	CipherSuitesChaCha20 = cipherSuites(chaCha20First)

	// CipherSuites3DES is a list of TLS cipher suites
	// that should only be offered if Should3DES
	// returns true.
	CipherSuites3DES = cipherSuites(include3DES)
)

// TLS13CipherSuites is a preferred list of TLS 1.3 cipher
// suites with AES-GCM before ChaCha20-Poly1305. It is
// intended for use with github.com/cloudflare/tls-tris.
//
// This will be removed if the TLS13CipherSuites field is
// eliminated.
var TLS13CipherSuites = []uint16{
	tlstris.TLS_AES_128_GCM_SHA256,
	tlstris.TLS_AES_256_GCM_SHA384,
	tlstris.TLS_CHACHA20_POLY1305_SHA256,
}

// TLS13CipherSuitesChaCha20 is a preferred list of TLS 1.3
// cipher suites with ChaCha20-Poly1305 before AES-GCM.
// It is intended for use with github.com/cloudflare/tls-tris.
//
// This will be removed if the TLS13CipherSuites field is
// eliminated.
var TLS13CipherSuitesChaCha20 = []uint16{
	tlstris.TLS_CHACHA20_POLY1305_SHA256,
	tlstris.TLS_AES_128_GCM_SHA256,
	tlstris.TLS_AES_256_GCM_SHA384,
}

type cipherSuiteTypes int

const (
	defaultSuites cipherSuiteTypes = 0
	chaCha20First cipherSuiteTypes = 1 << iota
	include3DES
)

func cipherSuites(typ cipherSuiteTypes) []uint16 {
	var cipherSuites []uint16

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

	cipherSuites = append(cipherSuites,
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

	if typ&include3DES == include3DES {
		// 3DES
		cipherSuites = append(cipherSuites,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	}

	return cipherSuites
}

// PrefersChaCha20 returns true iff a ChaCha20-Poly1305
// cipher suite is listed as the clients first preference.
func PrefersChaCha20(chi *tls.ClientHelloInfo) bool {
	id := chi.CipherSuites[0]
	return id == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 ||
		id == tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 ||
		id == tlstris.TLS_CHACHA20_POLY1305_SHA256
}

// Should3DES returns true iff 3DES cipher suites
// should be offered to the client. It returns
// true iff the client does not support TLS 1.1+.
func Should3DES(chi *tls.ClientHelloInfo) bool {
	for _, v := range chi.SupportedVersions {
		if v >= tls.VersionTLS11 {
			return false
		}
	}

	return true
}
