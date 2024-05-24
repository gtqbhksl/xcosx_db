package main

import (
	"fmt"
	"github.com/cheggaaa/pb/v3"
	bolt "go.etcd.io/bbolt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

func eulerdb() {
	ind := "https://repo.openeuler.org/security/data/cvrf/index.txt"
	resp, err := http.Get(ind)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
	}
	// 打开数据库
	db, err := bolt.Open("xcosx.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	lines := strings.Split(string(body), "\n")
	bar := pb.StartNew(len(lines))

	for _, line := range lines {
		bar.Increment()
		u := "https://repo.openeuler.org/security/data/cvrf/" + line
		//fmt.Println(u)
		Vulns := euler(u)
		if Vulns.OS == "openEuler" {
			fmt.Println("ERROR OS==nil", line)
			continue
		}

		for _, cve := range Vulns.CVE {
			for _, v := range Vulns.vuln {
				err := update(db, Vulns.OS, v.pack, v.version, cve)
				if err != nil {
					fmt.Println("ERROR:", err, line)
					continue
				}
			}
		}
	}
	bar.Finish()
}
