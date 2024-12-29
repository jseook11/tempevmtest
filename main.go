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

func generatePrivateKey() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func findMatchingAddress(prefixes, suffixes []string, result chan string, counter *int32, generatedCounter *int32, limit int32, stopChan chan struct{}) {
	for {
		select {
		case <-stopChan:
			return
		default:
			privateKeyHex := generatePrivateKey()

			// Increment the generated address counter
			atomic.AddInt32(generatedCounter, 1)

			privateKey, err := crypto.HexToECDSA(privateKeyHex)
			if err != nil {
				log.Fatal(err)
			}

			address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

			// Check for matching address
			for _, prefix := range prefixes {
				for _, suffix := range suffixes {
					if strings.HasPrefix(strings.ToLower(address), prefix) && strings.HasSuffix(strings.ToLower(address), suffix) {
						// Increment the found address counter
						if atomic.AddInt32(counter, 1) > limit {
							return
						}
						result <- fmt.Sprintf("Private Key: %s, Address: %s", privateKeyHex, address)
					}
				}
			}
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
	prefixes := []string{"0xaaaa", "0xbbbb", "0xcccc", "0xdddd", "0xeeee", "0x0000", "0x1111", "0x2222", "0x3333", "0x4444", "0x5555", "0x6666", "0x7777", "0x8888", "0x9999", "0xace"}
	suffixes := []string{""} // No specific suffixes
	workerCount := 8                                                                                                                                                     // Adjust based on CPU cores
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
