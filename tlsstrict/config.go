// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsstrict

import (
	"crypto/tls"

	"github.com/tmthrgd/tlsconfig/internal/tls-tris"
)

// Config clones config and sets safe, strict defaults.
func Config(config *tls.Config) *tls.Config {
	config = config.Clone()

	if config.CipherSuites == nil {
		config.PreferServerCipherSuites = true
		config.CipherSuites = CipherSuites
	}

	// Session Tickets do not refresh the key material
	// when using TLS 1.2 or earlier. The strict
	// configuration is intendended for long-lived
	// connections anyway.
	config.SessionTicketsDisabled = true
	config.ClientSessionCache = nil

	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

	if config.MaxVersion == 0 {
		config.MaxVersion = tlstris.VersionTLS13
	}

	if config.CurvePreferences == nil {
		config.CurvePreferences = CurvePreferences
	}

	// Renegotiation is dangerous and the source of bugs
	// and security issues. It is also useless for the
	// intended strict use case. Be explicit in disabling it.
	config.Renegotiation = tls.RenegotiateNever

	return config
}
