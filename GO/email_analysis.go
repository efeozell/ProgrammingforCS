package main

import (
	"log"
	"os"
	"strings"

	"github.com/sg3des/eml"
)

var (
	suspiciousSubjectLine = []string{
		"Urgent",
		"Verification required",
		"Invoice",
		"Need urgent help!",
		"Suspicious Outlook activity",
		"Important! Your password is about to expire",
		"Action required",
		"fail",
		"important",
		"notice",
	}

	suspiciousBody = []string{
		"A vulnerability has been identified in",
		"To perfom verification, click the link",
		"Please click here to install the latest",
		"account has been locked for security reasons",
		"fail",
		"important",
		"notice",
	}
)

func CheckForSuspiciousWords(email *eml.Message) (words []string, sus bool) {

	words = make([]string, 0, len(suspiciousSubjectLine)+len(suspiciousBody))

	body := strings.ToLower(string(email.Body))

	for _, word := range suspiciousBody {
		word = strings.ToLower(word)
		if strings.Contains(body, word) {
			sus = true
			words = append(words, word)
		}
	}

	subject := strings.ToLower(email.Subject)
	for _, word := range suspiciousSubjectLine {
		if strings.Contains(subject, word) {
			sus = true
			words = append(words, word)
		}
	}

	return
}

func CheckSenderValidity(email *eml.Message) {

	sender := email.Sender.Email()
	list := strings.Split(sender, "@")
	if len(list) < 2 {
		log.Fatal("FATAL could not retreive the domain name")
	}
	domain := list[1]

	for _, header := range email.FullHeaders {
		if header.Key == "Received" {
			values := strings.Split(header.Value, " ")
			if len(values) < 2 {
				log.Fatal("INVALID RECEIVED FORMAT ", len(values), header.Value)
			}
			if domain != values[1] {
				log.Printf("WARN the email might to be spoofed. Domain in senders email address and RECEIVED header do not match domain in email %s domain in RECEIVED header %s", domain, values[1])
			}
		}
	}

	replyTo := email.ReplyTo
	if len(replyTo) == 0 {
		log.Printf("WARN no return path for %s", sender)
	} else {
		replyEmail := replyTo[0].Email()
		if replyEmail != sender {
			log.Printf("WARN sender and return path is not equal. Email address in sender:%s and Email address in replyTo: %s\n", sender, replyEmail)
		}
	}
}

func main() {

	if len(os.Args) < 2 {
		log.Fatal("eml files not submitted. Usage: ./phishing <sample.eml>")
	}

	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("FATAL could not read content of the file", err)
	}

	m, err := eml.ParseRaw(content)
	if err != nil {
		log.Fatal("FATAL could not parse content due to error", err)
	}

	mail, _ := eml.Process(m)

	suspiciousWordsFound, ok := CheckForSuspiciousWords(&mail)
	if ok {
		log.Printf("WARN following suspicious words found in the email %v\n", suspiciousWordsFound)
	}
	CheckSenderValidity(&mail)
}
