package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func init() {
    rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklm-012345nopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandString(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
}
// 20000 rules: 80sec, fast=8.6sec, xfast=6ms
// 15000 rules: 44sec, fast=4sec , xfast=4ms
// 10000 rules: 20 sec
// 8000 rules: 10 sec
// 5000 rules: 4 sec
// 6000 rules: 6 sec
// 1000 rules: 133ms
const (
	ITERS = 13000
	SIZE = 50
)
func main () {

	test1_slow()
	test1_fast()
	test1_xfast()
}
func test1_xfast() {
	test1 := map[string]int{}
	test2 := map[string]int{}

	for i:=0 ; i <= ITERS/30; i++ {
		common := RandString(SIZE)
		test1[common] = i
		test2[common] = i
	}

	for i:=0 ; i <= ITERS; i++ {
		test1[RandString(SIZE)] = i

		test2[RandString(SIZE)] = i
	}
	startTime := time.Now()
	fmt.Printf("Start calculations..%d \n ", ITERS)

	equals := 0
	foundA := 0
	foundB := 0
	for k, _ := range test1 {
		words := strings.Split(k, "w")
		if strings.Contains(k, "-a") {
			foundA++
		}
        if _, ok := test2[k]; ok {
			if strings.Contains(k, "-d") {
				foundB++
			}
			words2 := strings.Split(k, "w")
			if words[0] == words2[0] {
				equals++
			}
		}
	}
	fmt.Printf("%d XFAST found %d equals in %v \n", ITERS, equals, time.Since(startTime))
}



func test1_slow() {
	test1 := map[string]int{}
	test2 := map[string]int{}

	for i:=0 ; i <= ITERS/30; i++ {
		common := RandString(SIZE)
		test1[common] = i
		test2[common] = i
	}

	for i:=0 ; i <= ITERS; i++ {
		test1[RandString(SIZE)] = i
		test2[RandString(SIZE)] = i
	}
	startTime := time.Now()
	fmt.Printf("Start calculations..%d \n ", ITERS)

	equals := 0
	foundA := 0
	foundB := 0
	for k, _ := range test1 {
		words := strings.Split(k, "w")
		if strings.Contains(k, "-a") {
			foundA++
		}

		for j := range test2 {
			if strings.Contains(j, "-d") {
				foundB++
			}
			words2 := strings.Split(j, "w")
			if words[0] == words2[0] {
				equals++
			}
		}
	}
	fmt.Printf("%d SLOW found %d equals in %v \n", ITERS, equals, time.Since(startTime))
}


func test1_fast() {
	test1 := map[string]int{}
	test2 := map[string]int{}

	for i:=0 ; i <= ITERS/30; i++ {
		common := RandString(SIZE)
		test1[common] = i
		test2[common] = i
	}

	for i:=0 ; i <= ITERS; i++ {
		test1[RandString(SIZE)] = i
		if i % 3 == 0 {
			test2[RandString(SIZE)] = i
		}

	}
	startTime := time.Now()
	fmt.Printf("Start calculations..%d \n ", ITERS)

	equals := 0

	for k, _ := range test1 {

		for j, _ := range test2 {

			if k == j {
				equals++
			}
		}
	}
	fmt.Printf("%d FAST found %d equals in %v \n", ITERS, equals, time.Since(startTime))
}
