// Copyright 2017 Tom Thorogood. All rights reserved.
// Use of this source code is governed by a
// Modified BSD License license that can be found in
// the LICENSE file.

package tlsconfig

import "crypto/tls"

// Config clones config and sets the list of cipher suites,
// curves.
func Config(config *tls.Config) *tls.Config {
	config = config.Clone()

	if config.CipherSuites == nil {
		config.PreferServerCipherSuites = true
		config.CipherSuites = CipherSuites
	}

	if config.CurvePreferences == nil {
		config.CurvePreferences = CurvePreferences
	}

	return config
}
