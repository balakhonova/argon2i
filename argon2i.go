/*
argon2i - strengthen passwords with Argon2i
Copyright (C) 2019-2024 Elena Balakhonova <balakhonova_e@riseup.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Argon2i - strengthen passwords with argon2i
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var (
	time      = flag.Uint("time", 3, "The number of passes over the memory")
	memory    = flag.Uint("memory", 32*1024, "Size of the memory in KiB")
	keyLength = flag.Uint("length", 32, "Key length in bytes")
	threads   = flag.Uint("threads", 4, "The number of threads")
	saltHex   = flag.String("salt", "", "Salt, hexadecimal, optional, random 8 bytes if empty")
)

func strengthenPasswd(
	weakPasswd, saltRaw []byte,
	time, memory, keyLength uint32,
	threads uint8,
) string {
	strengthenedPasswd := argon2.Key(
		weakPasswd,
		saltRaw,
		time,
		memory,
		threads,
		keyLength,
	)
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		"argon2i",
		argon2.Version,
		memory,
		time,
		threads,
		base64.RawStdEncoding.EncodeToString(saltRaw),
		base64.RawStdEncoding.EncodeToString(strengthenedPasswd),
	)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "argon2i - strengthen passwords with Argon2i\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	fmt.Printf("Enter your password: ")
	weakPasswd, err := term.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nEnter your password again: ")
	weakPasswd1, err := term.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	if !bytes.Equal(weakPasswd, weakPasswd1) {
		log.Fatal("Passwords do not match")
	}
	var salt []byte
	if len(*saltHex) == 0 {
		salt = make([]byte, 8)
		_, err = io.ReadFull(rand.Reader, salt)
	} else {
		salt, err = hex.DecodeString(*saltHex)
	}
	if err != nil {
		log.Fatal(err)
	}
	saltRaw := hex.EncodeToString(salt)
	fmt.Println(
		strengthenPasswd(
			weakPasswd,
			[]byte(saltRaw),
			uint32(*time),
			uint32(*memory),
			uint32(*keyLength),
			uint8(*threads),
		),
	)
}
