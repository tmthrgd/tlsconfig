// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build !go1.12

package internal

import "crypto/tls"

const VersionTLSLatest = tls.VersionTLS12

func IsTLS_CHACHA20_POLY1305_SHA256(uint16) bool { return false }
