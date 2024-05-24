package main

import (
	"encoding/xml"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	bolt "go.etcd.io/bbolt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// see http://oval.mitre.org/language/version5.11/ovaldefinition/documentation/oval-definitions-schema.html
type oval_definitions struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	ID       string      `xml:"id,attr"`
	Version  string      `xml:"version,attr"`
	Title    string      `xml:"metadata>title"`
	Platform string      `xml:"metadata>affected>platform"`
	CVEs     []string    `xml:"metadata>advisory>cve"`
	Comments []criterion `xml:"criteria>criteria>criterion"`
}
type criterion struct {
	Comment string `xml:"comment,attr"`
}

// 读取package、version
func getpvAnolis(s string) vuln {
	splitParts := strings.Split(s, " is earlier than ")

	packagePart := splitParts[0]
	versionPart := splitParts[1]
	return vuln{
		pack:    packagePart,
		version: versionPart,
	}
}
func download(url string) ([]byte, error) {
	//从https://anas.openanolis.cn/api/data/OVAL/anolis-7.oval.xml下载文件并读取解析
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("failed to fetch XML: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("failed to download XML (status code %d)\n", resp.StatusCode)
	}
	return ioutil.ReadAll(resp.Body)
}
func anolis7() {
	filePath := "https://anas.openanolis.cn/api/data/OVAL/anolis-7.oval.xml"
	data, err := download(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	v := oval_definitions{}
	err = xml.Unmarshal(data, &v)
	if err != nil {
		fmt.Println("Error unmarshalling", err)
		return
	}

	// 打开数据库
	db, err := bolt.Open("xcosx.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	bar := pb.StartNew(len(v.Definitions))
	for _, definition := range v.Definitions {
		bar.Increment()
		var Vulns Vulns
		for _, comment := range definition.Comments {
			pvAnolis := getpvAnolis(comment.Comment)
			Vulns.vuln = append(Vulns.vuln, pvAnolis)
		}
		Vulns.CVE = definition.CVEs
		Vulns.OS = "anolis7"

		for _, cve := range Vulns.CVE {
			for _, v := range Vulns.vuln {
				err := update(db, Vulns.OS, v.pack, v.version, cve)
				if err != nil {
					fmt.Println("ERROR:", err, Vulns.CVE)
					continue
				}
			}
		}
	}
	bar.Finish()
}

func anolis8() {
	filePath := "https://anas.openanolis.cn/api/data/OVAL/anolis-8.oval.xml"
	data, err := download(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	v := oval_definitions{}
	err = xml.Unmarshal(data, &v)
	if err != nil {
		fmt.Println("Error unmarshalling", err)
		return
	}

	// 打开数据库
	db, err := bolt.Open("xcosx.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	bar := pb.StartNew(len(v.Definitions))
	for _, definition := range v.Definitions {
		bar.Increment()
		var Vulns Vulns
		for _, comment := range definition.Comments {
			pvAnolis := getpvAnolis(comment.Comment)
			Vulns.vuln = append(Vulns.vuln, pvAnolis)
		}
		Vulns.CVE = definition.CVEs
		Vulns.OS = "anolis7"

		for _, cve := range Vulns.CVE {
			for _, v := range Vulns.vuln {
				err := update(db, Vulns.OS, v.pack, v.version, cve)
				if err != nil {
					fmt.Println("ERROR:", err, Vulns.CVE)
					continue
				}
			}
		}
	}
	bar.Finish()
}
