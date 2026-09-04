package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	VIRUSTOTAL_FEED = "https://www.virustotal.com/api/v3/ip_addresses/"
	API_KEY         = "MUST_BE_FILLED"
)

type LastAnalysisResults struct {
	Category   string `json:"category"`
	Result     string `json:"result"`
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
}

type FeedResponse struct {
	Data struct {
		Attributes struct {
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

var checkedIps = map[string]struct{}{}

func ReadPacket(filename string) {

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatalf("Unable to read from pcap file %v", err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packets.Packets() {

		network := packet.NetworkLayer()
		if network == nil {
			continue
		}
		netFlow := network.NetworkFlow()
		source, destination := netFlow.Endpoints()
		srcIp := net.ParseIP(source.String())
		dstIp := net.ParseIP(destination.String())
		ips := []string{}

		//if ips are not private then append the ips list
		if !srcIp.IsPrivate() {
			ips = append(ips, srcIp.String())
		}

		if !dstIp.IsPrivate() {
			ips = append(ips, dstIp.String())
		}

		lookup(ips)
	}
}

func lookup(ips []string) {
	for _, ip := range ips {
		maxRetries := 4
		for {
			maxRetries -= 1
			if _, ok := checkedIps[ip]; ok || maxRetries == 0 {
				break
			}
			url := VIRUSTOTAL_FEED + ip
			result := FeedResponse{}

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				fmt.Println("while crafting request for threat feed", err)
				break
			}
			req.Header.Set("x-apikey", API_KEY)

			client := http.Client{Timeout: 10 * time.Second}

			resp, err := client.Do(req)
			if err != nil {
				fmt.Println(err, "while querying threat feed")
				break
			}

			if resp.StatusCode == 204 {
				fmt.Println("VirusTotal API limit reached please try again")
				time.Sleep(1 * time.Minute)
				resp.Body.Close()
				continue
			}

			if resp.StatusCode != http.StatusOK {
				fmt.Println("Unexpected status code from VT:", resp.StatusCode)
				resp.Body.Close()
				break
			}

			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				fmt.Println("While unmarshalling json response", err)
				resp.Body.Close()
				break
			}

			if result.Data.Attributes.TotalVotes.Malicious > 0 {
				fmt.Println("[*] WARN found malicious IP address", ip, " hit count", result.Data.Attributes.TotalVotes.Malicious)
			}
			checkedIps[ip] = struct{}{}
			resp.Body.Close()
			break
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Not enough arguments. Please provide pcap file as argument. Ex: /.detect_sus_ip sample.pcap")
	}
	fmt.Println("[+] Reading packets now")
	ReadPacket(os.Args[1])
}
