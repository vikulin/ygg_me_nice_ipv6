/*

This go project generates nice ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd , etc

*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"strconv"
	"runtime"
	"github.com/cheggaaa/pb/v3"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
)

type keySet struct {
	priv []byte
	pub  []byte
	ip   []byte
}

func main() {
	flag.Parse()
	if(len(os.Args)==0) {
		fmt.Println("This go project generates nice Yggdrasil ipv6 addresses such as ...aaaa:bbbb...., abab:cdcd , etc")
		fmt.Println("Examples:")
		fmt.Println("This command will find single match for c0fe in IPv6 address:")
		fmt.Println("ygg_nice_ipv6.exe 1 1000000000 c0fe")
		fmt.Println("This command will find single match for :: in IPv6 address:")
		fmt.Println("ygg_nice_ipv6.exe 1 1000000000 00000000")
        	os.Exit(0)
	}
	matches_string := flag.Arg(0)
	attempts_string := flag.Arg(1)
	cores := runtime.NumCPU()
	fmt.Println(fmt.Sprintf("found CPU cores: %v\n",cores))
	matches, err := strconv.Atoi(matches_string)
	if err != nil {
        	// handle error
		fmt.Println("Run ygg_me_nice_ipv6 without arguments to see usage examples")
	        fmt.Println(err)
        	os.Exit(2)
	}
	attempts, err := strconv.Atoi(attempts_string)
	if err != nil {
        	// handle error
		fmt.Println("Run ygg_me_nice_ipv6 without arguments to see usage examples")
	        fmt.Println(err)
        	os.Exit(2)
	}
	bar := pb.StartNew(attempts)
	var encryptionKeys []keySet
	var wg sync.WaitGroup
	found := 0
	os.MkdirAll("keys", 0755)
	file, err := os.Create("keys/res.txt")
	if err != nil {
		return
	}
	
	if(len(os.Args)<=3){
		for core := 0; core < cores; core++ {
			wg.Add(1)
			go func(core int) {
				defer wg.Done()
				for a := 0; a < attempts/cores; a++ {
					key:=newBoxKey()
					if match_within_group(key.ip, matches){
						encryptionKeys = append(encryptionKeys, key)
						found++
						file.WriteString(fmt.Sprintf("yggdrasil_encryption_public_key: %v\n", hex.EncodeToString(key.pub)))
						file.WriteString(fmt.Sprintf("yggdrasil_encryption_private_key: %v\n", hex.EncodeToString(key.priv)))
						file.WriteString(fmt.Sprintf("ipv6: %v\n", net.IP(key.ip).String()))
						
					}
					bar.Increment()
				}
			}(core)
		}
	} else {
		special_bytes_string := flag.Arg(2)
		special_bytes, err := hex.DecodeString(special_bytes_string)
		if err != nil {
			// handle error
			fmt.Println(err)
			os.Exit(2)
		}
		fmt.Println(special_bytes)
		for core := 0; core < cores; core++ {
			wg.Add(1)
			go func(core int) {
				defer wg.Done()
				for a := 0; a < attempts/cores; a++ {
					key:=newBoxKey()
					if match_with_group(key.ip, matches, special_bytes){
						encryptionKeys = append(encryptionKeys, key)
						found++
						file.WriteString(fmt.Sprintf("yggdrasil_encryption_public_key: %v\n", hex.EncodeToString(key.pub)))
						file.WriteString(fmt.Sprintf("yggdrasil_encryption_private_key: %v\n", hex.EncodeToString(key.priv)))
						file.WriteString(fmt.Sprintf("ipv6: %v\n", net.IP(key.ip).String()))
						
					}
					bar.Increment()
				}
			}(core)
		}
	}
	wg.Wait()
	bar.Finish()
}

func match_within_group(s []byte, matches int) bool {
	m:=0
	for b:=0;b<15;b++{
	   if s[b]==s[b+1] {
	   	m++	
	   }
	}
	if m>=matches {
		return true
	}
	return false
}

func match_with_group(s []byte, matches int, special_bytes []byte) bool {
	m:=0
	for b:=2;b<=16-len(special_bytes);b=b+len(special_bytes){
		i:=0
		for sp:=0;sp<len(special_bytes);sp++{
		   if s[b+sp]==special_bytes[sp] {
		   	i++	
		   }
	   	}
	   	if i>=len(special_bytes){
			m++
	   	}
	}
	if m>=matches {
		return true
	}
	return false
}

func match_between_group(s []byte, matches int) bool {
	m:=0
	for b:=0;b<14;b++{
	   if s[b]==s[b+2] {
	   	m++	
	   }
	}
	if m>=matches {
		return true
	}
	return false
}

func newBoxKey() keySet {
	pub, priv := crypto.NewBoxKeys()
	id := crypto.GetNodeID(pub)
	ip := address.AddrForNodeID(id)[:]
	return keySet{priv[:], pub[:], ip}
}
