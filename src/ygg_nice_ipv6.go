/*

This go project generates nice ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd , etc

*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type keySet struct {
	privateKey []byte
	publicKey  []byte
	ip         []byte
}

func check(e error) {
	if e != nil {
		fmt.Println(fmt.Printf("Error occurred: %v", e))
		panic(e)
	}
}

func checkWithN(e error, n int) {
	if e != nil {
		fmt.Println(fmt.Printf("Error occurred: %v, Writed bytes: %v", e, n))
		panic(e)
	}
}

func main() {
	flag.Parse()
	if len(os.Args) == 1 {
		fmt.Println("This go project generates nice Yggdrasil ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd, and etc")
		fmt.Println("Examples:")
		fmt.Println("This command will find single match for c0fe in IPv6 address:")
		fmt.Println("ygg_nice_ipv6.exe 1 1000000000 c0fe")
		fmt.Println("This command will find single match for :: in IPv6 address:")
		fmt.Println("ygg_nice_ipv6.exe 1 1000000000 00000000")
		fmt.Println("This command will find beautiful address with 4 mirrored address blocks")
		fmt.Println("Example: 204:bdbd:44b5:9191:7e7e:1635:e3e3:3504")
		fmt.Println("ygg_nice_ipv6.exe 4 100000")
		os.Exit(0)
	}
	matchesString := flag.Arg(0)
	attemptsString := flag.Arg(1)
	cores := runtime.NumCPU()
	fmt.Println(fmt.Sprintf("found CPU cores: %v\n", cores))
	matches, err := strconv.Atoi(matchesString)
	if err != nil {
		// handle error
		fmt.Println("Run ygg_me_nice_ipv6 without arguments to see usage examples")
		fmt.Println(err)
		os.Exit(2)
	}
	attempts, err := strconv.Atoi(attemptsString)
	if err != nil {
		// handle error
		fmt.Println("Run ygg_me_nice_ipv6 without arguments to see usage examples")
		fmt.Println(err)
		os.Exit(2)
	}
	bar := pb.StartNew(attempts)
	bar.SetRefreshRate(time.Second) //console will not lag
	bar.SetWriter(os.Stdout)        //early it wrote to stderr
	var encryptionKeys []keySet
	var wg sync.WaitGroup
	found := 0
	err = os.MkdirAll("keys", 0755)
	check(err)
	file, err := os.Create("keys/res.txt")
	check(err)

	if len(os.Args) <= 3 {
		for core := 0; core < cores; core++ {
			wg.Add(1)
			go func(core int) {
				defer wg.Done()
				for a := 0; a < attempts/cores; a++ {
					key := newBoxKey()
					if matchWithinGroup(key.ip, matches) {
						encryptionKeys = append(encryptionKeys, key)
						found++
						n, err := file.WriteString(fmt.Sprintf("IPv6: %v\n", net.IP(key.ip).String()))
						checkWithN(err, n)
						n, err = file.WriteString(fmt.Sprintf("Yggdrasil_encryption_public_key: %v\n", hex.EncodeToString(key.publicKey)))
						checkWithN(err, n)
						n, err = file.WriteString(fmt.Sprintf("Yggdrasil_encryption_private_key: %v\n", hex.EncodeToString(key.privateKey)))
						checkWithN(err, n)
						n, err = file.WriteString("\n")
						checkWithN(err, n)

					}
					bar.Increment()
				}
			}(core)
		}
	} else {
		specialBytesString := flag.Arg(2)
		specialBytes, err := hex.DecodeString(specialBytesString)
		if err != nil {
			// handle error
			fmt.Println("Check you correctly entered special bytes parameter")
			fmt.Println(err)
			os.Exit(2)
		}
		fmt.Printf("Target: find %v %v times in address\n\n", specialBytesString, matchesString)
		n, err := file.WriteString(fmt.Sprintf("Target: find %v %v times in address\n\n", specialBytesString, matchesString))
		checkWithN(err, n)
		fmt.Println(specialBytes)
		for core := 0; core < cores; core++ {
			wg.Add(1)
			go func(core int) {
				defer wg.Done()
				for a := 0; a < attempts/cores; a++ {
					key := newBoxKey()
					if matchWithGroup(key.ip, matches, specialBytes) {
						encryptionKeys = append(encryptionKeys, key)
						found++
						n, err := file.WriteString(fmt.Sprintf("IPv6: %v\n", net.IP(key.ip).String()))
						checkWithN(err, n)
						n, err = file.WriteString(fmt.Sprintf("Yggdrasil_encryption_public_key: %v\n", hex.EncodeToString(key.publicKey)))
						checkWithN(err, n)
						n, err = file.WriteString(fmt.Sprintf("Yggdrasil_encryption_private_key: %v\n", hex.EncodeToString(key.privateKey)))
						checkWithN(err, n)
						n, err = file.WriteString("\n")
						checkWithN(err, n)

					}
					bar.Increment()
				}
			}(core)
		}
	}
	wg.Wait()
	bar.Finish()
}

func matchWithinGroup(s []byte, matches int) bool {
	m := 0
	for b := 2; b < 15; b = b + 2 {
		if s[b] == s[b+1] {
			m++
		}
	}
	if m >= matches {
		return true
	}
	return false
}

func matchWithGroup(s []byte, matches int, specialBytes []byte) bool {
	m := 0
	for b := 2; b <= 16-len(specialBytes); b = b + len(specialBytes) {
		i := 0
		for sp := 0; sp < len(specialBytes); sp++ {
			if s[b+sp] == specialBytes[sp] {
				i++
			}
		}
		if i >= len(specialBytes) {
			m++
		}
	}
	if m >= matches {
		return true
	}
	return false
}

//func matchBetweenGroup(s []byte, matches int) bool {
//	m:=0
//	for b:=0;b<14;b++{
//	   if s[b]==s[b+2] {
//	   	m++
//	   }
//	}
//	if m>=matches {
//		return true
//	}
//	return false
//}

func newBoxKey() keySet {
	publicKey, privateKey := crypto.NewBoxKeys()
	id := crypto.GetNodeID(publicKey)
	ip := address.AddrForNodeID(id)[:]
	return keySet{privateKey[:], publicKey[:], ip}
}
