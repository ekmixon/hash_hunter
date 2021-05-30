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
	"sync"
	"time"

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
var polyswarm string
var urlhaus string

var hashes = make([]string, 0)

func init() {
	config := readConfig(configFile)
	virusTotal = config["virusTotal"]
	hybridAnalysis = config["hybridAnalysis"]
	malwareBazaar = config["malwareBazaar"]
	malshare = config["malshare"]
	intezerAnalyze = config["intezerAnalyze"]
	maltiverse = config["maltiverse"]
	polyswarm = config["polyswarm"]
	urlhaus = config["urlhaus"]
}

func main() {
	defer timeTrack(time.Now())
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

func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	fmt.Printf("\n\nHash Hunter completed. Search took %s", elapsed)
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
			if !match {
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
	if !match {
		fmt.Println("[!] Invalid SHA256 hash.")
	}
	return match
}

// loop through API checks for each hash
func checkHashes() {
	for _, hash := range hashes {
		var waitgroup sync.WaitGroup
		waitgroup.Add(9)
		fmt.Printf("\n\n%v", hash)
		if virusTotal != "" {
			go func() {
				getVtCheck(hash)
				waitgroup.Done()
			}()
		}
		if hybridAnalysis != "" {
			go func() {
				getHACheck(hash)
				waitgroup.Done()
			}()
		}
		if malwareBazaar != "" {
			go func() {
				getMBCheck(hash)
				waitgroup.Done()
			}()
		}
		if malshare != "" {
			go func() {
				getMSCheck(hash)
				waitgroup.Done()
			}()
		}
		if intezerAnalyze != "" {
			go func() {
				getIntCheck(hash)
				waitgroup.Done()
			}()
		}
		if maltiverse != "" {
			go func() {
				getMaltiCheck(hash)
				waitgroup.Done()
			}()
		}
		if polyswarm != "" {
			go func() {
				getPolyCheck(hash)
				waitgroup.Done()
			}()
		}
		if urlhaus != "" {
			go func() {
				getUrlhausCheck(hash)
				waitgroup.Done()
			}()
		}
		go func() {
			getInQuest(hash)
			waitgroup.Done()
		}()
		waitgroup.Wait()
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
	if result.String() == "Not Found" || result.String() == "Sorry, this hash was reported for abuse and is not available" {
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
		if signature.String() == "" {
			fmt.Printf("\nMalware Bazaar: recorded as unknown")
		} else {
			fmt.Printf("\nMalware Bazaar: recorded as %v", signature)
		}
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
	res, err := client.Do(req)
	if err != nil {
		fmt.Print(err.Error())
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "message")
	if result.String() == "Not found" {
		fmt.Printf("\nMaltiverse: Not found")
	} else if result.String() == "Internal Server Error" {
		fmt.Printf("\nMaltiverse: Server Error")
	} else {
		verdict := gjson.Get(sb, "classification")
		fmt.Printf("\nMaltiverse: verdict is %v", verdict)
	}
}

func getInQuest(hash string) {
	url := ("https://labs.inquest.net/api/dfi/details?sha256=" + hash)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Basic null")
	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	result := gjson.Get(sb, "success")
	if result.String() == "false" {
		fmt.Printf("\nInQuest: Not found")
	} else {
		verdict := gjson.Get(sb, "data.classification")
		// s_verdict := verdict string(verdict)
		fmt.Printf("\nInQuest Labs: verdict is %v", strings.ToLower(verdict.String()))
	}
}

func getPolyCheck(hash string) {
	// TODO
}

func getUrlhausCheck(hash string) {
	apiUrl := ("https://urlhaus-api.abuse.ch/v1/payload/")

	data := url.Values{}
	data.Set("sha256_hash", hash)

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
	if result.String() == "no_results" {
		fmt.Printf("\nURLHaus: Not found")
	} else if result.String() == "ok" {
		signature := gjson.Get(sb, "signature")
		if signature.String() == "" {
			fmt.Printf("\nURLHaus: recorded as unknown")
		} else {
			fmt.Printf("\nURLHaus: recorded as %v", signature)
		}
	}
}
