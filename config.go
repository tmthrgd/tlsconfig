// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import (
	"crypto/tls"

	"github.com/tmthrgd/tlsconfig/internal/tls-tris"
)

// Config clones config and sets the list of cipher suites,
// curves and disabled renegotiation.
func Config(config *tls.Config) *tls.Config {
	config = config.Clone()

	if config.CipherSuites == nil {
		config.PreferServerCipherSuites = true
		config.CipherSuites = CipherSuites
		tlstris.SetTLS13CipherSuites(config, TLS13CipherSuites)
	}

	if config.CurvePreferences == nil {
		config.CurvePreferences = CurvePreferences
	}

	// Renegotiation is dangerous and the source of bugs
	// and security issues. Be explicit in disabling it.
	config.Renegotiation = tls.RenegotiateNever

	return config
}
