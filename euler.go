package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Vulnerability struct {
	XMLName       xml.Name `xml:"Vulnerability"`
	CVE           string   `xml:"CVE"`
	ProductStatus struct {
		Status struct {
			ProductID string `xml:"ProductID"`
		} `xml:"Status"`
	} `xml:"ProductStatuses"`
}

type Branch struct {
	Type            string `xml:"Type,attr"`
	Name            string `xml:"Name,attr"`
	FullProductName struct {
		ProductID string `xml:"ProductID,attr"`
		CPE       string `xml:"CPE,attr"`
		Value     string `xml:",chardata"`
	} `xml:"FullProductName"`
}

// 定义结构体映射XML结构
type ProductTree struct {
	XMLName xml.Name `xml:"ProductTree"`
	Branch  []Branch `xml:"Branch"`
}

type vuln struct {
	pack    string
	version string
}

type Vulns struct {
	CVE  []string
	vuln []vuln
	OS   string
}

func euler(url string) Vulns {
	time.Sleep(1)
	//url := "https://repo.openeuler.org/security/data/cvrf/2024/cvrf-openEuler-SA-2024-1356.xml"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching file:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))

	// Parse the XML data
	var vulns []Vulnerability
	var prodTree ProductTree
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "Vulnerability" {
				var vuln Vulnerability
				decoder.DecodeElement(&vuln, &t)
				vulns = append(vulns, vuln)
			} else if t.Name.Local == "ProductTree" {
				decoder.DecodeElement(&prodTree, &t)
			}
		}
	}

	// Print the extracted data
	var Vulns Vulns

	for _, vuln := range vulns {
		Vulns.CVE = append(Vulns.CVE, vuln.CVE)
	}
	for _, prod := range prodTree.Branch {
		if prod.Name == "src" {
			lens := len(strings.Split(prod.FullProductName.CPE, ":"))
			name := strings.Split(prod.FullProductName.CPE, ":")[lens-1]
			names := strings.Split(name, "-")[0]
			Vulns.OS = "openEuler" + names
			if lens == 4 {
				Vulns.OS = "openEuler"
			}
			v := strings.Split(prod.FullProductName.Value, ".src.rpm")[0]
			pv := getpv(v)
			Vulns.vuln = append(Vulns.vuln, pv)
		}
	}
	return Vulns

}

// 读取package、version
func getpv(s string) vuln {
	splitParts := strings.Split(s, "-")

	var k int

	for i, char := range splitParts {
		if char == "389" {
			continue
		}
		//判断char是不是数字开头的字符串
		if 48 <= char[0] {
			if char[0] <= 57 {
				k = i
				break
			}
		}
	}
	//splitParts的前k个用-连接
	packagePart := strings.Join(splitParts[:k], "-")
	//splitParts的k个之后用-连接
	versionPart := strings.Join(splitParts[k:], "-")

	return vuln{
		pack:    packagePart,
		version: versionPart,
	}

}
