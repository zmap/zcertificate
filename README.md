# ZCertificate

[![CI Status](https://github.com/zmap/zcertificate/workflows/Go/badge.svg)](https://github.com/zmap/zcertificate/actions?query=workflow%3AGo)
[![Lint Status](https://github.com/zmap/zcertificate/workflows/golangci-lint/badge.svg)](https://github.com/zmap/zcertificate/actions?query=workflow%3Agolangci-lint)

ZCertificate parses X.509 certificates and runs [ZLint](https://github.com/zmap/zlint).

### Installing ZCertificate

1. Pick an [ZCertificate release][releases] and download the `.tar.gz` archive for
   your architecture (for example `Linux_x86_64.tar.gz`):

       wget https://github.com/zmap/zcertificate/releases/download/v0.0.1/zcertificate_0.0.1_Linux_x86_64.tar.gz

1. Extract the archive and change into the extracted directory:

       tar xf zcertificate*.tar.gz
       cd zcertificate*

1. Make the `zcertificate` program executable:

       chmod +x zcertificate 

1. Run the `zcertificate` program:

       ./zcertificate

[releases]: https://github.com/zmap/zcertificate/releases

### Building from source

Building ZCertificate from source requires [Go 1.15.x or
newer](https://golang.org/doc/install). 

Assume the `go` command is in your `$PATH` you can build ZCertificate from
source with:

```bash
go get github.com/zmap/zcertificate/cmd/zcertificate
```

### Usage

```
$ ./zcertificate --help
Usage of ./zcertificate:
  -fatal-parse-errors
    	Halt if a certificate cannot be parsed. Default is to log.
  -json-parse-errors
    	Output json if a certificate cannot be parsed. Default is not to.
  -format string
    	one of {pem, base64} (default "pem")
  -output-file string
    	Specifies file path for the output JSON. (default "-")
  -procs int
    	Specifies number of processes to run on. Default is 0, meaning use current value of $GOMAXPROCS.
  -workers int
    	Specifies number of goroutines to use to parse and lint certificates. (default 1)

$ cat example.crt | zcertificate | jq .
INFO[0000] reading from stdin
INFO[0000] writing to stdout
{
  "raw": "...",
  "parsed": {
    "version": 3,
    "serial_number": "513",
    "signature_algorithm": {
      "name": "SHA1WithRSA",
      "oid": "1.2.840.113549.1.1.5"
    },
    "issuer": {
      "country": [
        "US"
      ],
  ...
}
```
