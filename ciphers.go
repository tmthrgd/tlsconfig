// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import "crypto/tls"

var (
	// CipherSuites is a preferred list of TLS cipher
	// suites with AES-GCM before ChaCha20-Poly1305.
	CipherSuites = cipherSuites(false, false)

	// CipherSuitesChaCha20 is a preferred list of TLS
	// cipher suites with ChaCha20-Poly1305 before
	// AES-GCM.
	CipherSuitesChaCha20 = cipherSuites(true, false)

	// CipherSuites3DES is a list of TLS cipher suites
	// that should only be offered if Should3DES
	// returns true.
	CipherSuites3DES = cipherSuites(false, true)
)

const (
	tls13AES128GCMSHA256        uint16 = 0x1301
	tls13AES256GCMSHA384        uint16 = 0x1302
	tls13CHACHA20POLY1305SHA256 uint16 = 0x1303
)

// TLS13CipherSuites is a preferred list of TLS 1.3 cipher
// suites with AES-GCM before ChaCha20-Poly1305. It is
// intended for use with github.com/cloudflare/tls-tris.
//
// This will be removed if the TLS13CipherSuites field is
// eliminated.
var TLS13CipherSuites = []uint16{
	tls13AES128GCMSHA256,
	tls13AES256GCMSHA384,
	tls13CHACHA20POLY1305SHA256,
}

// TLS13CipherSuitesChaCha20 is a preferred list of TLS 1.3
// cipher suites with ChaCha20-Poly1305 before AES-GCM.
// It is intended for use with github.com/cloudflare/tls-tris.
//
// This will be removed if the TLS13CipherSuites field is
// eliminated.
var TLS13CipherSuitesChaCha20 = []uint16{
	tls13CHACHA20POLY1305SHA256,
	tls13AES128GCMSHA256,
	tls13AES256GCMSHA384,
}

func cipherSuites(chaCha20First, threeDES bool) []uint16 {
	var cipherSuites []uint16

	if chaCha20First {
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

	if !chaCha20First {
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

	if threeDES {
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
		id == tls13CHACHA20POLY1305SHA256
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
