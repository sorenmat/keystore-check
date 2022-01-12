package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
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
	ttl := kingpin.Flag("ttl", "time to live, displays how long there is for a certificate to expire").Bool()
	kingpin.Parse()

	ks := readKeyStore(*path, []byte(*password))
	exit := 0
	if *ttl {
		result := map[string]int{}
		for _, a := range ks.Aliases() {
			tce, err := ks.GetTrustedCertificateEntry(a)
			if err != nil {
				log.Fatal(err)
			}

			cert, err := x509.ParseCertificates(tce.Certificate.Content)
			if err != nil {
				log.Fatal(err)
			}

			days := math.Round(cert[0].NotAfter.Sub(time.Now()).Hours() / 24)

			result[cert[0].Subject.CommonName] = int(days)
		}
		l := sortMap(result)
		for _, v := range l {
			fmt.Printf("%v\t%v\n", v.Value, v.Key)
		}
	} else {

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
	}
	os.Exit(exit)
}

func sortMap(wordFrequencies map[string]int) PairList {
	pl := make(PairList, len(wordFrequencies))
	i := 0
	for k, v := range wordFrequencies {
		pl[i] = Pair{k, v}
		i++
	}
	sort.Sort(pl)
	return pl
}

type Pair struct {
	Key   string
	Value int
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
