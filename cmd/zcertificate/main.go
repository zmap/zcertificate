/*
 * ZCrypto Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcertificate"
	"github.com/zmap/zcrypto/x509"
	zlint "github.com/zmap/zlint/v3"
)

var ( //flags
	outputFileName   string
	workers          int
	numProcs         int
	crashIfParseFail bool
	jsonIfParseFail  bool
	format           string
)

func init() {
	flag.StringVar(&outputFileName, "output-file", "-", "Specifies file path for the output JSON.")
	flag.IntVar(&workers, "workers", 1, "Specifies number of goroutines to use to parse and lint certificates.")
	flag.IntVar(&numProcs, "procs", 0, "Specifies number of processes to run on. Default is 0, meaning use current value of $GOMAXPROCS.")
	flag.BoolVar(&crashIfParseFail, "fatal-parse-errors", false, "Halt if a certificate cannot be parsed. Default is to log.")
	flag.BoolVar(&jsonIfParseFail, "json-parse-errors", false, "Output json if a certificate cannot be parsed. Default is not to.")
	flag.StringVar(&format, "format", "pem", "one of {pem, base64}")
	flag.Parse()
}

func appendZLintToCertificate(raw []byte, cert *x509.Certificate, zl *zlint.ResultSet, parseError error) ([]byte, error) {
	return json.Marshal(struct {
		Raw        []byte            `json:"raw,omitempty"`
		Parsed     *x509.Certificate `json:"parsed,omitempty"`
		ZLint      *zlint.ResultSet  `json:"zlint,omitempty"`
		ParseError error             `json:"error,omitempty"`
	}{
		Raw:        raw,
		Parsed:     cert,
		ZLint:      zl,
		ParseError: parseError,
	})
}

func processCertificate(in <-chan []byte, out chan<- []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	for raw := range in {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			// The certificate could not be parsed. Either error or halt.
			log.Errorf("could not parse certificate: %s", err)
			if crashIfParseFail {
				log.Fatal("parsing errors are fatal")
			}
			if !jsonIfParseFail {
				continue
			}
		}
		// The certificate was parsed (or not). Run ZLint on it.
		var zlintResult *zlint.ResultSet
		if parsed != nil {
			zlintResult = zlint.LintCertificate(parsed)
		}

		jsonResult, err := appendZLintToCertificate(raw, parsed, zlintResult, err)
		if err != nil {
			log.Fatal("could not marshal output JSON")
		}
		out <- jsonResult
	}
}

func writeOutput(in <-chan []byte, out io.Writer, wg *sync.WaitGroup) {
	defer wg.Done()
	for json := range in {
		_, _ = out.Write(json)
		_, _ = out.Write([]byte{'\n'})
	}
}

func main() {
	log.SetLevel(log.InfoLevel)
	runtime.GOMAXPROCS(numProcs)

	// Validate flag combinations
	if jsonIfParseFail && crashIfParseFail {
		log.Fatal("at most one of -json-parse-errors and -fatal-parse-errors may be specified")
	}

	// Open the input file
	var inputFile *os.File
	if flag.NArg() < 1 || flag.Arg(0) == "-" {
		inputFile = os.Stdin
		log.Info("reading from stdin")
	} else {
		inputFilePath := flag.Arg(0)

		var err error
		if inputFile, err = os.Open(inputFilePath); err != nil {
			log.Fatalf("unable to open input file %s: %s", inputFilePath, err)
		}
		defer inputFile.Close()
		log.Infof("reading from %s", inputFile.Name())
	}

	// Open the output file
	var outputFile *os.File
	if outputFileName == "" || outputFileName == "-" {
		outputFile = os.Stdout
		log.Info("writing to stdout")
	} else {
		var err error
		outputFile, err = os.Create(outputFileName)
		if err != nil {
			log.Fatalf("unable to create output file: %s", err)
		}
		defer outputFile.Close()
		log.Infof("writing to %s", outputFile.Name())
	}

	// Initialize channels.
	incomingCertBytes := make(chan []byte, workers*4)
	outgoingJSONBytes := make(chan []byte, workers*4)

	// Start the input reader
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	switch f := strings.ToLower(format); f {
	case "pem":
		go func() {
			_ = zcertificate.BreakPEMAsync(incomingCertBytes, inputFile, "CERTIFICATE", &readerWG)
		}()
	case "base64":
		go func() {
			_ = zcertificate.BreakBase64ByLineAsync(incomingCertBytes, inputFile, &readerWG)
		}()
	default:
		log.Fatalf("invalid --format: %s", format)
	}

	// Start the output writer
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go writeOutput(outgoingJSONBytes, outputFile, &writerWG)

	// Start the workers
	var procWG sync.WaitGroup
	procWG.Add(workers)
	for i := 0; i < workers; i++ {
		go processCertificate(incomingCertBytes, outgoingJSONBytes, &procWG)
	}

	// Wait for the input reader to finish, then close the certificate channel.
	readerWG.Wait()
	close(incomingCertBytes)

	// Wait for the processors to drain the certificate channel, then close the
	// output channel.
	procWG.Wait()
	close(outgoingJSONBytes)

	// Wait for the output writer to finish.
	writerWG.Wait()
}
