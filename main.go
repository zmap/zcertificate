package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/zlint"
	"os"
	"runtime"
	"sync"
	"github.com/zmap/zlint/lints"
)

var ( //flags
	inPath           string
	outPath          string
	numCertThreads   int
	prettyPrint      bool
	numProcs         int
	channelSize      int
	crashIfParseFail bool
	format           string
)

func init() {
	flag.StringVar(&inPath, "input-file", "-", "Specifies file path for the input certificate(s).")
	flag.StringVar(&outPath, "output-file", "-", "Specifies file path for the output JSON.")
	flag.BoolVar(&prettyPrint, "list-lints-json", false, "Prints supported lints in JSON format, one per line")
	flag.IntVar(&numCertThreads, "threads", 1, "Specifies number of threads in -threads mode. Default is 1.")
	flag.IntVar(&numProcs, "procs", 0, "Specifies number of processes to run on. Default is 0, meaning keep it the same as previously set")
	flag.IntVar(&channelSize, "channel-size", 1000, "Specifies number of values in the buffered channel. Default is 1000")
	flag.BoolVar(&crashIfParseFail, "fatal-parse-errors", false, "Fatally crashes if a certificate cannot be parsed. Log by default.")
	flag.StringVar(&format, "format", "pem", "one of {pem, base64}")
	flag.Parse()
}

func scannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}

func appendZLintToCertificate(cert *x509.Certificate, lintResult *lints.LintReport) ([]byte, error){
	return json.Marshal(struct {
		Raw	[]byte		   `json:"raw,omitempty"`
		Parsed  *x509.Certificate  `json:"parsed,omitempty"`
		ZLint	*lints.LintReport  `json:"zlint,omitempty"`
	}{
		Raw:	cert.Raw,
		Parsed:	cert,
		ZLint:	lintResult,
	})
}

func ProcessCertificate(in <-chan []byte, out chan<- []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	for raw := range in {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil { //could not parse
			if crashIfParseFail {
				log.Fatalf("could not parse certificate with error: %s", err)
			} else {
				log.Warnf("could not parse certificate with error: %s", err)
			}
		} else { //parsed
			zlintResult := zlint.ZLintResultTestHandler(parsed)
			jsonResult, err := appendZLintToCertificate(parsed, zlintResult.ZLint)
			if err != nil {
				log.Fatal("could not parse JSON.")
			}
			out <- jsonResult
		}
	}
}

func ReadCertificatePEM(out chan<- []byte, filename string, wg *sync.WaitGroup) {
	log.Info("Reading PEM certificates...")
	defer wg.Done()
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Split(scannerSplitPEM)
		for scanner.Scan() {
			certBytes, _ := pem.Decode(scanner.Bytes())
			if certBytes == nil {
				log.Warnf("could not correctly decode PEM input file: %s", err)
				continue
			}
			out <- certBytes.Bytes
		}
	}
}

func ReadCertificateBase64(out chan<- []byte, filename string, wg *sync.WaitGroup) {
	log.Info("Reading base64 certificates...")
	defer wg.Done()
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			certBytes, err := base64.StdEncoding.DecodeString(scanner.Text())
			if err != nil {
				log.Warnf("could not correctly decode b64 input file: %s", err)
				continue
			}
			out <- certBytes
		}
		if err = scanner.Err(); err != nil {
			log.Fatal("error with scanning file: ", err)
		}
	} else {
		log.Fatal("error reading file: ", err)
	}
}

func WriteOutput(in <-chan []byte, outputFileName string, wg *sync.WaitGroup) {
	defer wg.Done()
	var outFile *os.File
	var err error
	if outputFileName == "" || outputFileName == "-" {
		outFile = os.Stdout
	} else {
		outFile, err = os.Create(outputFileName)
		if err != nil {
			log.Fatal("Unable to create output file: ", err)
		}
		defer outFile.Close()
	}

	for json := range in {
		outFile.Write(json)
		outFile.Write([]byte{'\n'})
	}
}

func main() {
	log.SetLevel(log.InfoLevel)
	runtime.GOMAXPROCS(numProcs)

	if prettyPrint {
		zlint.PrettyPrintZLint()
		return
	}

	//Initialize Channels
	certs := make(chan []byte, channelSize)
	jsonOut := make(chan []byte, channelSize)

	var readerWG sync.WaitGroup
	var procWG sync.WaitGroup
	var writerWG sync.WaitGroup

	readerWG.Add(1)
	writerWG.Add(1)

	if format == "pem" {
		go ReadCertificatePEM(certs, inPath, &readerWG)
	} else if format == "base64" {
		go ReadCertificateBase64(certs, inPath, &readerWG)
	} else {
		log.Fatalf("invalid --format: provided %s", format)
	}

	go WriteOutput(jsonOut, outPath, &writerWG)

	for i := 0; i < numCertThreads; i++ {
		procWG.Add(1)
		go ProcessCertificate(certs, jsonOut, &procWG)
	}

	go func() {
		readerWG.Wait()
		close(certs)
	}()

	procWG.Wait()
	close(jsonOut)
	writerWG.Wait()
}
