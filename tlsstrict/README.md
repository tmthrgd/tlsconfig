# tlsstrict

[![GoDoc](https://godoc.org/github.com/tmthrgd/tlsconfig/tlsstrict?status.svg)](https://godoc.org/github.com/tmthrgd/tlsconfig/tlsstrict)

A sane, common, strict and secure TLS configuration for Golang projects.

It is intended for internal communication between private services.

## Protocols

![tls versions](protocols.png)

## Cipher Suites

### RSA

![cipher suites with an RSA certificate](rsa-cipher-suites.png)

### ECDSA

![cipher suites with an ECDSA certificate](ecdsa-cipher-suites.png)

## Curves

![curves](curves.png)

## Handshake Simulation

### RSA

![handshake simulation with an RSA certificate](rsa-handshakes.png)

### ECDSA

![handshake simulation with an ECDSA certificate](ecdsa-handshakes.png)
