// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import "crypto/tls"

// CipherSuites returns a list of cipher suites.
//
// If chaCha20First is true, then
// TLS_ECDHE_*_WITH_CHACHA20_POLY1305 will be preferred over
// TLS_ECDHE_*_WITH_AES_*_GCM_SHA*.
//
// If threeDES is true, then TLS_*_RSA_WITH_3DES_EDE_CBC_SHA
// will be included as the last preference. A cipher suite
// list with 3DES should only be offered to TLS 1.0 clients.
func CipherSuites(chaCha20First, threeDES bool) []uint16 {
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
