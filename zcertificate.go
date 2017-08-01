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

import "encoding/pem"

// ScannerSplitPEM is a split function for a bufio.Scanner that breaks input
// into chunks that can be handled by pem.Decode().
func ScannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}
