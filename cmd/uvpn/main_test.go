package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadSecretLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(" p&+% \r\n123456\n"))
	b, err := readLine(r)
	if err != nil || string(b) != " p&+% " {
		t.Fatal("secret line modified", err)
	}
	b, err = readLine(r)
	if err != nil || string(b) != "123456" {
		t.Fatal("buffered second factor lost", err)
	}
	if _, err = readLine(bufio.NewReader(strings.NewReader(strings.Repeat("a", 129) + "\n"))); err == nil {
		t.Fatal("oversized secret accepted")
	}
}
