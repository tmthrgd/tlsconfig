// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import "crypto/tls"

// CurvePreferences is a list of optimised
// TLS curves. It prefers X25519 over P-256.
var CurvePreferences = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
}
