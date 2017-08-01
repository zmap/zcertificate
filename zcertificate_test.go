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

package zcertificate

import (
	"bufio"
	"encoding/pem"
	"strings"
	"testing"

	data "github.com/zmap/zcrypto/data/test/certificates"
)

var pemTests = []struct {
	In    string
	Count int
}{
	{
		In:    data.PEMDAdrianIOSignedByLEX3,
		Count: 1,
	},
	{
		In:    data.PEMDAdrianIOSignedByLEX3 + "\n" + data.PEMDSTRootCAX3SignedBySelf,
		Count: 2,
	},
	{
		In:    data.PEMDAdrianIOSignedByLEX3 + "\n" + data.PEMDoDInteropCA2SignedByFederalBridgeCA + "\ngoop",
		Count: 2,
	},
	{
		Count: 0,
	},
}

func TestScannerSplitPEM(t *testing.T) {
	for idx, test := range pemTests {
		r := strings.NewReader(test.In)
		scanner := bufio.NewScanner(r)
		scanner.Split(ScannerSplitPEM)
		var i int
		for i = 0; scanner.Scan(); i++ {
			b := scanner.Bytes()
			p, rest := pem.Decode(b)
			if p == nil {
				t.Errorf("%d: could not parse PEM in position %d", idx, i)
			}
			if len(rest) > 0 {
				t.Errorf("%d: extra bytes at position %d", idx, i)
			}
		}
		if test.Count != i {
			t.Errorf("%d: expected %d, got %d PEM", idx, test.Count, i)
		}
	}
}
