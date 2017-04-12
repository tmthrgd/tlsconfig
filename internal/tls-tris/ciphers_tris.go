// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

// +build tls_tris

package tlstris

import "crypto/tls"

// SetTLS13CipherSuites sets TLS13CipherSuites to the
// provided list of cipher suites if the tls_tris build
// tag is specified, otherwise it does nothing. It
// returns true iff it TLS13CipherSuites was set.
//
// This will be removed once TLS 1.3 support is merged
// into crypto/tls, or if the TLS13CipherSuites field is
// eliminated.
func SetTLS13CipherSuites(config *tls.Config, suites []uint16) bool {
	config.TLS13CipherSuites = suites
	return true
}
