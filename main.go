package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/pavel-v-chernykh/keystore-go/v4"
	"gopkg.in/alecthomas/kingpin.v2"
)

func readKeyStore(filename string, password []byte) keystore.KeyStore {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		log.Fatal(err)
	}

	return ks
}

func main() {
	path := kingpin.Arg("path", "path to JKS").Required().String()
	password := kingpin.Arg("password", "JKS password").Required().Envar("JKS_PASSWORD").String()

	kingpin.Parse()

	ks := readKeyStore(*path, []byte(*password))
	exit := 0
	for _, a := range ks.Aliases() {
		tce, err := ks.GetTrustedCertificateEntry(a)
		if err != nil {
			log.Fatal(err)
		}

		cert, err := x509.ParseCertificates(tce.Certificate.Content)
		if err != nil {
			log.Fatal(err)
		}
		if time.Now().After(cert[0].NotAfter) {
			fmt.Printf("%v expired at %v\n", cert[0].Subject.CommonName, cert[0].NotAfter)
			exit = 1
		}
	}
	os.Exit(exit)
}
