package main

import (
	"fmt"
	"testing"
)

func TestIDP(t *testing.T) {
	tokens := idpVerify()
	fmt.Println("accessToken:", tokens.AccessToken)
}
