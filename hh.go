package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

var hash = flag.String("h", "", "SHA256 hash to search for")
var file = flag.String("f", "", "Text file path containing hashes")

var configFile = "config.json"

var virusTotal string
var hybridAnalysis string
var malwareBazaar string
var malshare string
var intezerAnalyze string
var maltiverse string

var hashes = make([]string, 0)

func init() {
	config := readConfig(configFile)
	virusTotal = config["virusTotal"]
	hybridAnalysis = config["hybridAnalysis"]
	malwareBazaar = config["malwareBazaar"]
	malshare = config["malshare"]
	intezerAnalyze = config["intezerAnalyze"]
	maltiverse = config["maltiverse"]
}

func main() {
	flag.Parse()

	if *hash != "" {
		hashes = append(hashes, *hash)
	} else if *file != "" {
		openFile(*file)
	} else {
		enterHash()
	}
	checkHashes()
}

func readConfig(filename string) map[string]string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	var data map[string]string
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		log.Fatal(err)
	}
	return data
}

func openFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hashes = append(hashes, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func enterHash() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter hashes. Press ENTER to finish.")
	for {
		fmt.Print("hash: ")
		scanner.Scan()
		text := scanner.Text()
		if len(text) != 0 {
			match := verifySha256(text)
			if match == false {
				continue
			}
			hashes = append(hashes, text)
		} else {
			break
		}
	}
}

// check validity of SHA256
func verifySha256(hash string) bool {
	match, _ := regexp.MatchString("[A-Fa-f0-9]{64}", hash)
	if match != true {
		fmt.Println("[!] Invalid SHA256 hash.")
	}
	return match
}

// loop through API checks for each hash
func checkHashes() {
	for _, hash := range hashes {
		fmt.Printf("\n\n%v", hash)
		if virusTotal != "" {
			getVtCheck(hash)
		}
		if hybridAnalysis != "" {
			getHACheck(hash)
		}
		if malwareBazaar != "" {
			getMBCheck(hash)
		}
		if malshare != "" {
			getMSCheck(hash)
		}
		if intezerAnalyze != "" {
			getIntCheck(hash)
		}
		if maltiverse != "" {
			getMaltiCheck(hash)
		}
	}
}

// Check Virus Total
func getVtCheck(hash string) {
	url := ("https://www.virustotal.com/api/v3/files/" + hash)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", virusTotal)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "error.code")
	if result.String() == "NotFoundError" {
		fmt.Printf("\nVirus Total: Not found")
	} else {
		malicious := gjson.Get(sb, "data.attributes.last_analysis_stats.malicious")
		undetected := gjson.Get(sb, "data.attributes.last_analysis_stats.undetected")

		fmt.Printf("\nVirus Total: %v malicious, %v undetected", malicious, undetected)
	}
}

// Check Hybrid Analysis
func getHACheck(hash string) {
	url := ("https://www.hybrid-analysis.com/api/v2/overview/" + hash)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("api-key", hybridAnalysis)
	req.Header.Add("user-agent", "Falcon Sandbox")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "message")
	if result.String() == "Not Found" {
		fmt.Printf("\nHybrid Analysis: Not found")
	} else {
		verdict := gjson.Get(sb, "verdict")
		fmt.Printf("\nHybrid Analysis: verdict is %v", verdict)
	}
}

// check Malware Bazaar
func getMBCheck(hash string) {
	apiUrl := ("https://mb-api.abuse.ch/api/v1/")

	data := url.Values{}
	data.Set("query", "get_info")
	data.Set("hash", hash)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, apiUrl, strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "query_status")
	if result.String() == "hash_not_found" {
		fmt.Printf("\nMalware Bazaar: Not found")
	} else if result.String() == "ok" {
		signature := gjson.Get(sb, "data.0.signature")
		fmt.Printf("\nMalware Bazaar: recorded as %v", signature)
	} else {
		fmt.Printf("\nMalware Bazaar: error")
	}
}

// Check MalShare
func getMSCheck(hash string) {
	url := ("http://www.malshare.com/api.php?api_key=" + malshare + "&action=details&hash=" + hash)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "ERROR.MESSAGE")
	if result.String() == "Sample not found" {
		fmt.Printf("\nMalShare: Not found")
	} else {
		available := gjson.Get(sb, "SHA256")
		if available.String() == hash {
			fmt.Printf("\nMalShare: sample available")
		}
	}
}

// check Intezer Analyse
func getIntCheck(hash string) {
	baseUrl := "https://analyze.intezer.com/api/v2-0"

	// First get JWT token via API key. Need to pass API key in JSON byte slice.
	tokenUrl := baseUrl + "/get-access-token"
	var jsonData = []byte(fmt.Sprintf(`{"api_key":"%v"}`, intezerAnalyze))
	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, tokenUrl, bytes.NewBuffer(jsonData))
	req.Header.Add("Content-Type", "application/json; charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)

	// now use JWT to make request in regards to the specific hash
	token := gjson.Get(sb, "result")
	bearer := "Bearer " + token.String()
	filesUrl := baseUrl + "/files/" + hash
	reqToken, _ := http.NewRequest("GET", filesUrl, nil)
	reqToken.Header.Add("Authorization", bearer)
	clientToken := &http.Client{}
	respToken, err := clientToken.Do(reqToken)
	if err != nil {
		fmt.Print(err.Error())
	}
	bodyToken, err := ioutil.ReadAll(respToken.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sbToken := string(bodyToken)
	result := gjson.Get(sbToken, "error")
	if result.String() == "Analysis was not found" {
		fmt.Printf("\nIntezer: Not found")
	} else {
		verdict := gjson.Get(sbToken, "result.verdict")
		fmt.Printf("\nIntezer: verdict is %v", verdict)
	}
}

// check Maltiverse
func getMaltiCheck(hash string) {
	url := ("https://api.maltiverse.com/sample/" + hash)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	bearer := "Bearer " + maltiverse
	req.Header.Add("Authorization", bearer)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "message")
	if result.String() == "Not found" {
		fmt.Printf("\nMaltiverse: Not found")
	} else {
		verdict := gjson.Get(sb, "classification")
		fmt.Printf("\nMaltiverse: verdict is %v", verdict)
	}
}
