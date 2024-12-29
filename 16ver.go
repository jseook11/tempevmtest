package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func generatePrivateKeyBase() string {
	bytes := make([]byte, 32) // 31 bytes for the base key
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func generateModifiedKeys(baseKey string) []string {
	suffixes := []string{"a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	var keys []string
	baseKeyWithoutLast := baseKey[:len(baseKey)-1]

	// Replace the last character with each valid suffix
	for _, suffix := range suffixes {
		keys = append(keys, baseKeyWithoutLast+suffix)
	}
	return keys
}

func findMatchingAddress(
	prefixes, suffixes []string,
	result chan string,
	counter *int32,
	generatedCounter *int32,
	limit int32,
	stopChan chan struct{},
) {
	for {
		select {
		case <-stopChan:
			return
		default:
			baseKey := generatePrivateKeyBase()
			privateKeys := generateModifiedKeys(baseKey)

			// Increment the generated address counter for 16 keys
			atomic.AddInt32(generatedCounter, int32(len(privateKeys)))

			var wg sync.WaitGroup
			for _, privateKeyHex := range privateKeys {
				wg.Add(1)
				go func(pkHex string) {
					defer wg.Done()
					privateKey, err := crypto.HexToECDSA(pkHex)
					if err != nil {
						log.Fatal(err)
					}

					address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

					// Check for matching address
					for _, prefix := range prefixes {
						for _, suffix := range suffixes {
							if strings.HasPrefix(strings.ToLower(address), prefix) &&
								strings.HasSuffix(strings.ToLower(address), suffix) {
								// Increment the found address counter
								if atomic.AddInt32(counter, 1) > limit {
									close(stopChan)
									return
								}
								result <- fmt.Sprintf("Private Key: %s, Address: %s", pkHex, address)
							}
						}
					}
				}(privateKeyHex)
			}
			wg.Wait()
		}
	}
}

func writeResultsToFile(result chan string, filePath string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for res := range result {
		_, err := file.WriteString(res + "\n")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Found and saved:", res)
	}
}

func printStatus(startTime time.Time, counter *int32, generatedCounter *int32) {
	ticker := time.NewTicker(1 * time.Minute) // Tick every minute
	defer ticker.Stop()

	for range ticker.C {
		elapsed := time.Since(startTime)
		addressesFound := atomic.LoadInt32(counter)
		addressesGenerated := atomic.LoadInt32(generatedCounter)
		fmt.Printf("Running for: %v | Addresses Generated: %d | Addresses Found: %d\n", elapsed, addressesGenerated, addressesFound)
	}
}

func main() {
	prefixes := []string{"0xaaaaa", "0xbbbbb", "0xccccc", "0xddddd", "0xeeeee", "0x00000", "0x11111", "0x22222", "0x33333", "0x44444", "0x55555", "0x66666", "0x77777", "0x88888", "0x99999"}
	suffixes := []string{"aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee", "fffff", "00000", "11111", "22222", "33333", "44444", "55555", "66666", "77777", "88888", "99999"}
	workerCount := 8 // Adjust based on CPU cores
	result := make(chan string, workerCount)
	stopChan := make(chan struct{})
	filePath := "results.txt"

	var counter int32
	var generatedCounter int32
	limit := int32(100) // Stop after finding 100 addresses

	// Capture start time
	startTime := time.Now()

	// Launch workers
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findMatchingAddress(prefixes, suffixes, result, &counter, &generatedCounter, limit, stopChan)
		}()
	}

	// Start the status ticker in a separate goroutine
	go printStatus(startTime, &counter, &generatedCounter)

	// Write results to file
	go func() {
		writeResultsToFile(result, filePath)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(result)
	close(stopChan)

	fmt.Println("Address generation completed. Results saved to", filePath)
}
