// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsstrict

import (
	"crypto/tls"

	"github.com/tmthrgd/tlsconfig/internal/tls-tris"
)

// CipherSuites is a preferred list of TLS cipher
// suites with AES-GCM before ChaCha20-Poly1305.
var CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// TLS13CipherSuites is a preferred list of TLS 1.3 cipher
// suites with AES-GCM before ChaCha20-Poly1305. It is
// intended for use with github.com/cloudflare/tls-tris.
//
// This will be removed if the TLS13CipherSuites field is
// eliminated.
var TLS13CipherSuites = []uint16{
	tlstris.TLS_AES_256_GCM_SHA384,
	tlstris.TLS_CHACHA20_POLY1305_SHA256,
}