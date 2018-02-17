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
	}

	if config.MaxVersion == 0 {
		config.MaxVersion = tlstris.VersionTLS13
	}

	if config.CurvePreferences == nil {
		config.CurvePreferences = CurvePreferences
	}

	// Renegotiation is dangerous and the source of bugs
	// and security issues. Be explicit in disabling it.
	config.Renegotiation = tls.RenegotiateNever

	return config
}

// GetConfigForClient returns a GetConfigForClient function
// that automatically handles switching *tls.Config's for
// ChaCha20-Poly1305 and 3DES as required.
func GetConfigForClient(config *tls.Config) func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	return func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if PrefersChaCha20(chi) {
			configChaCha20 := config.Clone()
			configChaCha20.CipherSuites = CipherSuitesChaCha20
			return configChaCha20, nil
		} else if Should3DES(chi) {
			config3DES := config.Clone()
			config3DES.CipherSuites = CipherSuites3DES
			return config3DES, nil
		}

		return nil, nil
	}
}
