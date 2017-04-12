// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlstris

// These are redeclared from github.com/cloudflare/tls-tris.
//
// This will be removed once TLS 1.3 support is merged
// into crypto/tls.
const (
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303
)
