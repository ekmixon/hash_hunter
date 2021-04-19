# Hash Hunter  

A simple program for finding if a hash exists on various malware repositories. No more, no less. Useful if you just want to check where a sample might be available. 

Currently implemented 
- Virus Total
- Hybrid Analysis
- MalShare
- Malware Bazaar
- Intezer
- Maltiverse

## Usage 

```
-f <path/to/file> 
    List of SHA256 hashes separated by carriage return.  
-h <SHA256 hash> 
    Single SHA256 hash that you want to check for.  
```

If you don't specify `-f` or `-h` then you will be presented with the option to manually enter SHA256 hashes.  

## Dependencies

Enter your API keys for each service. Add these to a config file `config.json` as per below:  

```
{"virusTotal":"KEY",
"hybridAnalysis":"KEY",
"malwareBazaar":"KEY",
"malshare":"KEY",
"maltiverse":"KEY",
"intezerAnalyze":"KEY"}
```

If you are going to build from source you'll also need the below module for JSON parsing. 

```
go get github.com/tidwall/gjson
```

## Sample Output

```
PS C:\> go run .\hh.go -h e4a877ba15d80c1fb13c22ac4c90c7211452082f8d65f4393646e480cedffb3b

e4a877ba15d80c1fb13c22ac4c90c7211452082f8d65f4393646e480cedffb3b
Virus Total: 13 malicious, 46 undetected
Hybrid Analysis: verdict is malicious
Malware Bazaar: Not found
MalShare: Not found
Intezer: Not found
Maltiverse: verdict is malicious
```
