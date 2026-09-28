package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"bannerfp/internal/jsonx"
	"bannerfp/internal/model"
)

func main() {
	os.Exit(run())
}

func run() int {
	input := flag.String("input", "/data/input.json", "input JSON file")
	server := flag.String("server", "http://server:8080", "server base URL")
	format := flag.String("format", "json", "output format: json or table")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP timeout")
	retries := flag.Int("retries", 3, "retry count for transient failures")
	flag.Parse()

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		return 2
	}

	var items []model.Item
	lenient, err := jsonx.UnmarshalLenient(data, &items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse input: %v\n", err)
		return 2
	}
	if lenient {
		fmt.Fprintln(os.Stderr, `warning: input used non-standard \xNN escapes; applied compatibility parsing`)
	}

	payload, err := json.Marshal(items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode payload: %v\n", err)
		return 2
	}

	endpoint := strings.TrimRight(*server, "/") + "/fingerprint"
	client := &http.Client{Timeout: *timeout}
	var lastErr error
	for attempt := 0; attempt <= *retries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintf(os.Stderr, "build request: %v\n", err)
			return 3
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
			} else if resp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			} else {
				var results []model.Result
				if err := json.Unmarshal(body, &results); err != nil {
					fmt.Fprintf(os.Stderr, "decode response: %v\n", err)
					return 4
				}
				printResults(results, *format)
				return 0
			}
		}

		if attempt < *retries {
			fmt.Fprintf(os.Stderr, "attempt %d failed: %v; retrying\n", attempt+1, lastErr)
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
	fmt.Fprintf(os.Stderr, "fingerprint request failed: %v\n", lastErr)
	return 3
}

func printResults(results []model.Result, format string) {
	if format == "table" {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONFIDENCE")
		for _, result := range results {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
				result.IP, result.Port, result.Protocol, result.Product, result.Version, result.OSHint, result.Confidence)
		}
		_ = w.Flush()
		return
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(results)
}
