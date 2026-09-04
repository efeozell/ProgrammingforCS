package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type authoLoginInfo struct {
	sourceIP   string
	SourcePort string
	count      int
	Username   string
}

const (
	SSH_SERVICE      = "sshd"
	PASSWORD_FAILURE = "Failed password"
	THRESHOLD        = 10
)

func parseLog(logLine string) authoLoginInfo {
	val := authoLoginInfo{}
	strLog := string(logLine)
	if strings.Contains(strLog, SSH_SERVICE) && strings.Contains(strLog, PASSWORD_FAILURE) {
		afterFor := strings.Split(strLog, "for")

		if len(afterFor) < 2 {
			fmt.Println("ERROR could not understand log format, unable to split log using from charecter")
			os.Exit(-1)
		}

		infoS := strings.Split(afterFor[1], " ")
		if len(infoS) < 6 {
			fmt.Println("length not enough")
			return val
		}
		val.sourceIP = infoS[3]
		val.Username = infoS[1]
		val.SourcePort = infoS[5]
	}
	return val
}

func bruteDetect(filename string) {
	ipToFailure := map[string]authoLoginInfo{}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("ERROR could not open file", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		info := parseLog(line)
		if value, ok := ipToFailure[info.sourceIP]; ok {
			value.count += 1
			ipToFailure[info.sourceIP] = value
		} else {
			ipToFailure[info.sourceIP] = info
		}
		if err == io.EOF {
			break
		}
	}

	for ip, failure := range ipToFailure {
		if failure.count >= THRESHOLD {
			fmt.Printf("Possible brute force detection from IP %s with count %d\n", ip, failure.count)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("ERROR please provide log ")
	}
	bruteDetect(os.Args[1])
}
