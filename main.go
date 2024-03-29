// Copyright (c) 2019, Grégoire Duchêne <gduchene@awhk.org>
//
// Use of this source code is governed by the ISC license that can be
// found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"go.awhk.org/core"
)

var (
	caFlags   = flag.NewFlagSet(os.Args[0]+" ca", flag.ExitOnError)
	certFlags = flag.NewFlagSet(os.Args[0]+" cert", flag.ExitOnError)

	caName     = certFlags.String("ca", "", "base name for the CA files")
	commonName string
	country    string
	dnsNames   = core.FlagSlice(certFlags, "dns", nil, "DNS name", core.ParseString, ",")
	duration   time.Duration
	from       time.Time
	ips        = core.FlagSlice(certFlags, "ip", nil, "IP addresses", netip.ParseAddr, ",")
	keyAlgo    string
	org        []string
	out        string
	unit       []string
	until      time.Time
	usages     = core.FlagSlice(certFlags, "usage", []string{"server-auth"}, `how the certificate will be used:
  - code-signing
  - server-auth
`, core.ParseStringEnum("code-signing", "server-auth"), ",")
)

func init() {
	log.SetFlags(0)

	for _, f := range []*flag.FlagSet{caFlags, certFlags} {
		f.StringVar(&commonName, "cn", "", "common name")
		f.StringVar(&country, "c", "", "country code")
		f.DurationVar(&duration, "d", 0, "certificate duration")
		f.StringVar(&keyAlgo, "key-algo", "ecdsa", `key algorithm:
  - ecdsa
  - rsa
`)
		core.FlagSliceVar(f, &org, "o", "organization", core.ParseString, ",")
		core.FlagVar(f, &from, "nb", "the earliest time on which the certificate is valid", core.ParseTime)
		core.FlagSliceVar(f, &org, "o", "organization", core.ParseString, ",")
		f.StringVar(&out, "out", "", "base name for the output")
		core.FlagSliceVar(f, &unit, "ou", "organizational unit", core.ParseString, ",")
		core.FlagVar(f, &until, "na", "the time past which the certificate is no longer valid", core.ParseTime)
	}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `%s is a tool for generating certificates.

Usage:

	%[1]s <command> [arguments]

The commands are:

	ca     generate a CA certificate
	cert   generate a regular certificate

Use %[1]s <command> -h for help about that command.

`, os.Args[0])
	}
}

func main() {
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "ca":
		caFlags.Parse(os.Args[2:])
	case "cert":
		certFlags.Parse(os.Args[2:])
	default:
		flag.Usage()
		os.Exit(2)
	}
	if commonName == "" {
		log.Fatalln("error: -cn is required")
	}
	if country == "" {
		log.Fatalln("error: -c is required")
	}
	// See RFC 6125§6.4.4.
	if len(*dnsNames) > 0 || len(*ips) > 0 {
		*dnsNames = append(*dnsNames, commonName)
	}
	sort.Strings(*dnsNames)
	if from.IsZero() {
		from = time.Now()
	}
	if out == "" {
		log.Fatalln("error: -out is required")
	}
	if len(org) == 0 {
		log.Fatalln("error: -o is required")
	}
	if until.IsZero() {
		if duration == 0 {
			log.Fatalln("error: -na is required when no -d is passed")
		}
		until = from.Add(duration)
	} else if duration != 0 {
		log.Println("warning: ignored -d as -na was passed")
	}
	if until.Before(from) {
		log.Fatalln("error: end date is before the start date")
	}

	key, pubKey, err := keyPair()
	if err != nil {
		log.Fatalln("error: could not generate the certificate key:", err)
	}
	tmpl := &x509.Certificate{
		BasicConstraintsValid: os.Args[1] == "ca",
		DNSNames:              *dnsNames,
		ExtKeyUsage:           extKeyUsage(),
		IPAddresses:           core.SliceMap(func(ip netip.Addr) net.IP { return ip.AsSlice() }, *ips),
		IsCA:                  os.Args[1] == "ca",
		KeyUsage:              keyUsage(),
		NotBefore:             from,
		NotAfter:              until,
		SerialNumber:          newSerial(),
		Subject: pkix.Name{
			CommonName:         commonName,
			Country:            []string{country},
			Organization:       org,
			OrganizationalUnit: unit,
		},
		// See RFC 5280§4.2.1.2, a unique value is sufficient.
		SubjectKeyId: newSerial().Bytes(),
	}
	parentKey := key
	parentCert := tmpl
	if *caName != "" {
		buf, err := os.ReadFile(*caName + ".key")
		if err != nil {
			log.Fatalln("error: could not read the CA private key:", err)
		}
		block, _ := pem.Decode(buf)
		if block == nil {
			log.Fatalln("error: could not decode the private key block")
		}
		parentKey, err = parsePrivateKey(block)
		if err != nil {
			log.Fatalln("error: could not parse the CA private key:", err)
		}
		buf, err = os.ReadFile(*caName + ".crt")
		if err != nil {
			log.Fatalln("error: could not read the CA certificate:", err)
		}
		block, _ = pem.Decode(buf)
		if block == nil {
			log.Fatalln("error: could not decode the certificate block")
		}
		parentCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalln("error: could not parse the CA certificate:", err)
		}
		tmpl.AuthorityKeyId = parentCert.SubjectKeyId
	}
	if tmpl.NotBefore.Before(parentCert.NotBefore) {
		log.Fatalf("error: certificate starts before (%v) its parent (%v)",
			tmpl.NotBefore, parentCert.NotBefore)
	}
	if tmpl.NotAfter.After(parentCert.NotAfter) {
		log.Fatalf("error: certificate expires after (%v) its parent (%v)",
			tmpl.NotAfter, parentCert.NotAfter)
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pubKey, parentKey)
	if err != nil {
		log.Fatalln("error: could not generate the certificate:", err)
	}
	keyOut, err := os.OpenFile(out+".key", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalln("error: could not create the private key:", err)
	}
	defer keyOut.Close()
	certOut, err := os.OpenFile(out+".crt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln("error: could not create the certificate:", err)
	}
	defer certOut.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalln("error: could not serialize the private key:", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		log.Fatalln("error: could not encode the private key:", err)
	}
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		log.Fatalln("error: could not encode the certificate:", err)
	}
}

func extKeyUsage() []x509.ExtKeyUsage {
	if os.Args[1] == "ca" {
		return nil
	}
	s := map[string]x509.ExtKeyUsage{}
	for _, e := range *usages {
		switch e {
		case "code-signing":
			s[e] = x509.ExtKeyUsageCodeSigning
		case "server-auth":
			s[e] = x509.ExtKeyUsageServerAuth
		default:
			log.Fatalln("error: unknown key usage:", e)
		}
	}
	es := []x509.ExtKeyUsage{}
	for _, e := range s {
		es = append(es, e)
	}
	return es
}

func keyPair() (crypto.PrivateKey, crypto.PublicKey, error) {
	switch keyAlgo {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return key, &key.PublicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", keyAlgo)
	}
}

func keyUsage() x509.KeyUsage {
	if os.Args[1] == "ca" {
		return x509.KeyUsageCertSign
	}
	return x509.KeyUsageDigitalSignature
}

func newSerial() *big.Int {
	// Bound the number generation so the serial number does not take
	// up more than 20 octets. See Section 4.1.2.2 of RFC 5280 for more
	// details (https://tools.ietf.org/html/rfc5280#section-4.1.2.2).
	max := big.NewInt(2)
	max = max.Lsh(max, 159)
	max = max.Sub(max, big.NewInt(1))
	x, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	// We generated a random number between between [0, 2^160 - 1), so we
	// increment the result to get a serial number between [1, 2^160) as
	// serial numbers must be positive non-zero integers. See Erratum 3200
	// for more details (https://www.rfc-editor.org/errata/eid3200).
	return x.Add(x, big.NewInt(1))
}

func parsePrivateKey(b *pem.Block) (crypto.PrivateKey, error) {
	switch b.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(b.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(b.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", b.Type)
	}
}
