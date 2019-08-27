// Copyright (c) 2019, Grégoire Duchêne <gduchene@awhk.org>
//
// Use of this source code is governed by the ISC license that can be
// found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

type IPListFlag []net.IP

func (f *IPListFlag) String() string {
	var l []net.IP = *f
	return fmt.Sprintf("%s", l)
}

func (f *IPListFlag) Set(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return errors.New("could not parse IP")
	}
	*f = append(*f, ip)
	return nil
}

type StringListFlag []string

func (f *StringListFlag) String() string {
	var l []string = *f
	return fmt.Sprintf("%s", l)
}

func (f *StringListFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

type TimeFlag struct {
	t time.Time
}

func (f *TimeFlag) String() string {
	return f.t.String()
}

func (f *TimeFlag) Set(s string) (err error) {
	f.t, err = time.Parse(time.RFC3339, s)
	return
}

var (
	caName     = flag.String("ca", "", "base name for the CA files")
	commonName = flag.String("cn", "", "common name")
	country    = flag.String("c", "", "country code")
	dnsNames   StringListFlag
	duration   = flag.Duration("d", 0, "certificate duration")
	from       TimeFlag
	ips        IPListFlag
	org        StringListFlag
	out        = flag.String("out", "", "base name for the output")
	unit       StringListFlag
	until      TimeFlag
)

func init() {
	flag.Var(&dnsNames, "dns", "DNS name")
	flag.Var(&from, "nb", "the earliest time on which the certificate is valid")
	flag.Var(&ips, "ip", "IP address")
	flag.Var(&org, "o", "organization")
	flag.Var(&unit, "ou", "organizational unit")
	flag.Var(&until, "end-date", "certificate end date")
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

func main() {
	flag.Parse()
	log.SetFlags(0)

	if *commonName == "" {
		log.Fatalln("error: -cn is required")
	}
	if *country == "" {
		log.Fatalln("error: -c is required")
	}
	if from.t.IsZero() {
		from.t = time.Now()
	}
	if *out == "" {
		log.Fatalln("error: -out is required")
	}
	if len(org) == 0 {
		log.Fatalln("error: -o is required")
	}
	if until.t.IsZero() {
		if *duration == 0 {
			log.Fatalln("error: -end-date is required when no -d is passed")
		}
		until.t = from.t.Add(*duration)
	} else if *duration != 0 {
		log.Println("warning: ignored -d as -end-date was passed")
	}
	if until.t.Before(from.t) {
		log.Fatalln("error: end date is before the start date")
	}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalln("error: could not generate the certificate key:", err)
	}
	var (
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
	)
	if *caName == "" {
		keyUsage = x509.KeyUsageCertSign
	} else {
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	tmpl := &x509.Certificate{
		BasicConstraintsValid: *caName == "",
		DNSNames:              dnsNames,
		ExtKeyUsage:           extKeyUsage,
		IPAddresses:           ips,
		IsCA:                  *caName == "",
		KeyUsage:              keyUsage,
		NotBefore:             from.t,
		NotAfter:              until.t,
		SerialNumber:          newSerial(),
		Subject: pkix.Name{
			CommonName:         *commonName,
			Country:            []string{*country},
			Organization:       org,
			OrganizationalUnit: unit,
		},
	}
	parentKey := key
	parentCert := tmpl
	if *caName != "" {
		buf, err := ioutil.ReadFile(fmt.Sprintf("%s.key", *caName))
		if err != nil {
			log.Fatalln("error: could not read the CA private key:", err)
		}
		block, _ := pem.Decode(buf)
		parentKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Fatalln("error: could not parse the CA private key:", err)
		}
		buf, err = ioutil.ReadFile(fmt.Sprintf("%s.crt", *caName))
		if err != nil {
			log.Fatalln("error: could not read the CA certificate:", err)
		}
		block, _ = pem.Decode(buf)
		parentCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalln("error: could not parse the CA certificate:", err)
		}
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		log.Fatalln("error: could not generate the certificate:", err)
	}

	keyOut, err := os.OpenFile(fmt.Sprintf("%s.key", *out), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalln("error: could not create the private key:", err)
	}
	defer keyOut.Close()
	certOut, err := os.OpenFile(fmt.Sprintf("%s.crt", *out), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln("error: could not create the certificate:", err)
	}
	defer certOut.Close()
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatalln("error: could not serialize the private key:", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
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
