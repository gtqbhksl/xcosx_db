package main

import (
	"fmt"
	bolt "go.etcd.io/bbolt"
	"log"
	"strings"
	"time"
)

func update(db *bolt.DB, osname string, packagename string, version string, CVE string) error {
	var err error
	// 更新数据
	err = db.Update(func(tx *bolt.Tx) error {
		// 获取OSname桶
		osNameBucket := tx.Bucket([]byte(osname))
		if osNameBucket == nil {
			osNameBucket, _ = tx.CreateBucket([]byte(osname))
			//return fmt.Errorf(osname, "OSname bucket not found")
		}

		// 检查是否存在名为PackName2的packname桶
		packNameBucket := osNameBucket.Bucket([]byte(packagename))
		if packNameBucket == nil {
			// 如果不存在，则创建名为PackName2的packname桶
			packNameBucket, err = osNameBucket.CreateBucketIfNotExists([]byte(packagename))
			if err != nil {
				return err
			}
		}

		//// 在PackName2桶中写入新的key-value对
		//vull := vulns{"1.0.0", "CVE-2023-1234"}
		//// 将vuln结构序列化为二进制数据
		//var vulnBytes bytes.Buffer
		//enc := gob.NewEncoder(&vulnBytes)
		//err := enc.Encode(&vull)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//version := "20.20121asdasd-sdafsd4fasdg"
		//CVE := "CVE-2222-2222"

		err = packNameBucket.Put([]byte(version), []byte(CVE))
		if err != nil {
			return err
		}
		//fmt.Printf("Key: %s, Value: %s written to PackName2 bucket\n", key, value)

		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
	return err
}

type dbvulns struct {
	version string
	cve     string
}
type existvulns struct {
	packname   string
	version    string
	cve        string
	Fixversion string
}

func ReadDB(db *bolt.DB, osname string, packagename string) []dbvulns {
	var dbvulnS []dbvulns
	// 读取数据
	err := db.View(func(tx *bolt.Tx) error {
		// 获取OSname桶
		osNameBucket := tx.Bucket([]byte(osname))
		if osNameBucket == nil {
			return fmt.Errorf("OSname bucket not found")
		}

		// 获取packname桶
		packNameBucket := osNameBucket.Bucket([]byte(packagename))
		if packNameBucket == nil {
			return fmt.Errorf("packname bucket not found")
		}

		// 遍历version桶下的CVE信息
		err := packNameBucket.ForEach(func(k, v []byte) error {
			//fmt.Printf("version: %s, cve: %s\n", k, v)
			dbvuln := dbvulns{string(k), string(v)}
			dbvulnS = append(dbvulnS, dbvuln)
			return nil
		})

		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil
	} else {
		return dbvulnS
	}
}

func compare(db *bolt.DB, osname string, packname string, version string, release string) []existvulns {
	var existvuln []existvulns
	dbvulnS := ReadDB(db, osname, packname)
	for _, dbvuln := range dbvulnS {

		fmt.Println(dbvuln)
		verlens := strings.Split(dbvuln.version, ":")
		vsver := verlens[len(verlens)-1]
		vsvers := strings.Split(vsver, "-")

		vsverVersion := vsvers[0]
		vsverRelease := vsvers[1]

		versions := strings.Split(version, ".")
		vsverVersions := strings.Split(vsverVersion, ".")

		for i, versionss := range versions {
			if strings.Compare(versionss, vsverVersions[i]) < 0 {
				//优化比较，先比较位数再比较大小
				if len(versionss) == len(vsverVersions[i]) {
					if versionss < vsverVersions[i] {
						fmt.Println("优化比较结果：", versionss, "<", vsverVersions[i])
						existvuln = append(existvuln, existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
						continue
					}
				} else {
					if len(versionss) < len(vsverVersions[i]) {
						fmt.Println("优化比较结果：", versionss, "<", vsverVersions[i])
						existvuln = append(existvuln, existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
						continue
					}
				}
			}
		}

		releases := strings.Split(release, ".")
		vsverReleases := strings.Split(vsverRelease, ".")

		for i, releasess := range releases {
			//优化比较，先比较位数再比较大小
			if len(releasess) == len(vsverReleases[i]) {
				if releasess < vsverReleases[i] {
					fmt.Println("优化比较结果：", releasess, "<", vsverReleases[i])
					existvuln = append(existvuln, existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
					continue
				}
			} else {
				if len(releasess) < len(vsverReleases[i]) {
					fmt.Println("优化比较结果：", releasess, "<", vsverReleases[i])
					existvuln = append(existvuln, existvulns{packname, version + "-" + release, dbvuln.cve, vsver})
					continue
				}
			}
		}
	}
	return existvuln
}
func msain() {

	// 打开数据库
	db, err := bolt.Open("xcosx.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	version := "7.79.1"
	realese := "1-2.1"
	var Existvuln [][]existvulns
	PackExistvuln := compare(db, "openEuler22.03", "curl", version, realese)
	fmt.Println(PackExistvuln)
	Existvuln = append(Existvuln, PackExistvuln)
	fmt.Println(len(Existvuln))

}
