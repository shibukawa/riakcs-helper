/*
    Copyright 2014, Yoshiki Shibukawa

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
 */

package main;

import (
	"os"
	"os/user"
	"fmt"
	"log"
	"flag"
	"time"
	"io"
	"io/ioutil"
	"sort"
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
)

var b64 = base64.StdEncoding

const usageStr = `Usage:

Config:
	riakcs-helper init [host] [adminAccessKey] [adminSecretKey] [adminId] [*proxy*]

User Operations:
	riakcs-helper create-user [userName] [email]
	riakcs-helper modify-user [oldName] [newUserName] [newEmail]
	riakcs-helper show-user [*userName*]
	riakcs-helper issue-credential [userName]
	riakcs-helper enable-user [userName]
	riakcs-helper disable-user [userName]

Bucket Operations:
	riakcs-helper create-bucket [bucketName] [*accesibleUserName*]
		: Create bucket. If user name is passed,
		: give read/write access to specified user (owner is admin)
	riakcs-helper delete-bucket [*-f*] [bucketName]
	riakcs-helper clean-bucket [bucketName]
	riakcs-helper list [*bucketName*]
	riakcs-helper set-acl [bucketName] [accesibleUserName]
		: give read/write access to specified user (owner is admin)

User and Bucket Operations:
	riakcs-helper create-project [bucketAndUserName] [email]
		: Create user and bucket (both have same name)
		: New user has READ/WRITE access of the new bucket.

note:
	[parameter] is required. [*param*] is optional.
`

func usage() {
	fmt.Fprintln(os.Stderr, usageStr)
	flag.PrintDefaults()
}

type RiakUser struct {
	Email string
	Display_name string
	Key_id string
	Key_secret string
	Name string
	Id string
	Status string
}

type RiakUsers []*RiakUser

func (b RiakUsers) Len() int {
	return len(b)
}

func (b RiakUsers) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b RiakUsers) Less(i, j int) bool {
	return b[i].Name < b[j].Name
}

type Config struct {
	AdminAccessKey string
	AdminSecretKey string
	AdminId string
	Host string
	Proxy string
}

func readConfig() *Config {
	usr, _ := user.Current()
	path := filepath.Join(usr.HomeDir, ".riakcs_helper")
	in, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(in)
	in.Close()
	if err != nil {
		log.Fatal(err)
	}
	config := Config{}
	err = json.Unmarshal(body, &config)
	if err != nil {
		log.Fatal(err)
	}
	return &config
}

func writeConfig(host, adminAccessKey, adminSecretKey, adminId, proxy string) {
	usr, _ := user.Current()
	path := filepath.Join(usr.HomeDir, ".riakcs_helper")
	config := Config{adminAccessKey, adminSecretKey, adminId, host, proxy}
	b, _ := json.Marshal(config)
	out, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Printf("setting file %s is written.\n", path)
	out.Write(b)
	out.Close()
}

func createClient(config *Config) *http.Client {
	client := &http.Client{}
	if config.Proxy != "" {
		urlObj := url.URL{}
		urlProxy, err := urlObj.Parse(config.Proxy)
		if err != nil {
			log.Fatal(err)
		}
		transport := &http.Transport{}
		transport.Proxy = http.ProxyURL(urlProxy)
		// setting for ssl
		// transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = transport
	}
	return client
}

func sign(req *http.Request, config *Config, md5, contentType, signUrl string) {
	t := time.Now()
	adminAccessKey := config.AdminAccessKey
	adminSecretKey := config.AdminSecretKey
	dateStr := t.UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", dateStr)
	if md5 != "" {
		req.Header.Set("Content-MD5", md5)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	str_to_sign := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", req.Method, md5, contentType, dateStr, signUrl)
	//log.Println(str_to_sign)
	hash := hmac.New(sha1.New, []byte(adminSecretKey))
	hash.Write([]byte(str_to_sign))

	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))
	req.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", adminAccessKey, string(signature)))
}

func createUser(name, email string) *RiakUser {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}
	host := config.Host
	url := fmt.Sprintf("http://%s/riak-cs/user", host)
	requestBody := fmt.Sprintf("{\"email\":\"%s\",\"name\":\"%s\"}", email, name)
	client := createClient(config)
	req, _ := http.NewRequest("POST", url, strings.NewReader(requestBody))

	sign(req, config, "", "application/json", "/riak-cs/user")

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != 201 {
		log.Fatalln("User creation failed.")
	}
	var user RiakUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}
	return &user
}

func findUser(name string) *RiakUser {
	users := getAllUsers()
	for _, user := range users {
		if user.Name == name {
			return user
		}
	}
	return nil
}

func loadAdmin(config *Config) *RiakUser {
	var admin RiakUser
	admin.Id = config.AdminId
	admin.Display_name = "Administrator"
	return &admin
}

func getAllUsers() []*RiakUser {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}
	url := fmt.Sprintf("http://%s/riak-cs/users",  config.Host)
	client := createClient(config)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")

	sign(req, config, "", "application/json", "/riak-cs/users")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != 200 {
		log.Fatalln("Getting user failed.")
	}

	mediaType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal(nil)
	}
	if mediaType != "multipart/mixed" {
		log.Fatal("unknown return type. this code assumes multipart/mixed")
	}
	mr := multipart.NewReader(res.Body, params["boundary"])
	resultUsers := make([]*RiakUser, 0)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return resultUsers
		}
		if err != nil {
			log.Fatal(err)
		}
		var users []RiakUser
		body, err := ioutil.ReadAll(part)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(body, &users)
		if err != nil {
			log.Fatal(err)
		}
		if len(users) == 0 {
			break
		}
		resultUsers = append(resultUsers, &users[0])
	}
	return resultUsers
}

func modifyUserSetting(userName, requestBody string) *RiakUser {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}

	foundUser := findUser(userName)
	if foundUser == nil {
		fmt.Printf("User %s is not found\n", userName)
		return nil
	}

	url := fmt.Sprintf("http://%s/riak-cs/user/%s", config.Host, foundUser.Key_id)

	client := createClient(config)
	req, _ := http.NewRequest("PUT", url, strings.NewReader(requestBody))

	sign(req, config, "", "application/json", fmt.Sprintf("/riak-cs/user/%s", foundUser.Key_id))

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	//log.Print(string(body))
	if err != nil {
		log.Fatal(err)
	}
	var user RiakUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}
	return &user

}

func modifyUser(oldUserName, newUserName, newEmail string) *RiakUser {
	requestBody := fmt.Sprintf(`{"name":"%s","email":"%s"}`, newUserName, newEmail)
	return modifyUserSetting(oldUserName, requestBody)
}

func issueNewUserCredential(userName string) *RiakUser {
	return modifyUserSetting(userName, `{"new_key_secret":true}`)
}

func setEnableUser(userName, enableFlag string) *RiakUser {
	requestBody := fmt.Sprintf(`{"status":"%s"}`, enableFlag)
	return modifyUserSetting(userName, requestBody)
}

func dumpUser(user *RiakUser) {
	fmt.Printf("  name:         %s\n", user.Name)
	fmt.Printf("  display-name: %s\n", user.Display_name)
	fmt.Printf("  email:        %s\n", user.Email)
	fmt.Printf("  id:           %s\n", user.Id)
	fmt.Printf("  access-key:   %s\n", user.Key_id)
	fmt.Printf("  secret-key:   %s\n", user.Key_secret)
	fmt.Printf("  status:       %s\n", user.Status)
}

type BucketQueryResult struct {
	Buckets BucketsResult `xml:"Buckets"`
}

type BucketsResult struct {
	Bucket []BucketResult `xml:"Bucket"`
}

type BucketResult struct {
	Name string
	CreationDate string
}

type BucketResults []BucketResult

func (b BucketResults) Len() int {
	return len(b)
}

func (b BucketResults) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b BucketResults) Less(i, j int) bool {
	return b[i].Name < b[j].Name
}

func listBuckets() {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
		return
	}

	client := createClient(config)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s", config.Host), strings.NewReader(""))
	req.Header.Set("Host", fmt.Sprintf("http://%s", config.Host))

	sign(req, config, "", "", "/")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != 200 {
		fmt.Println(res.Status)
		return
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("bucket list")
	var query BucketQueryResult
	xml.Unmarshal(body, &query)
	var buckets BucketResults = query.Buckets.Bucket
	sort.Sort(buckets)
	for _, bucket := range buckets {
		fmt.Printf("  %s : created at %s\n", bucket.Name, bucket.CreationDate)
	}
}

func accessBucket(bucket, method string, expectReturnCode int) (bool, string) {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
		return false, ""
	}

	client := createClient(config)
	req, _ := http.NewRequest(method, fmt.Sprintf("http://%s.%s", bucket, config.Host), strings.NewReader(""))
	req.Header.Set("Host", fmt.Sprintf("http://%s.%s", bucket, config.Host))

	sign(req, config, "", "", fmt.Sprintf("/%s/", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != expectReturnCode {
		fmt.Println(res.Status)
		return false, ""
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	return true, string(body)
}

func deleteContentRaw(client *http.Client, config *Config, bucket, content string) bool {
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("http://%s.%s/%s", bucket, config.Host, content), strings.NewReader(""))
	req.Header.Set("Host", fmt.Sprintf("http://%s.%s", bucket, config.Host))

	sign(req, config, "", "", fmt.Sprintf("/%s/%s", bucket, content))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != 204 {
		fmt.Println(res.Status)
		return false
	}
	return true
}

func deleteContent(bucket, content string) bool {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
		return false
	}

	client := createClient(config)
	return deleteContentRaw(client, config, bucket, content)
}

func cleanBucket(bucket string) {
	contents := listBucketContents(bucket)
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
		os.Exit(1)
	}
	client := createClient(config)
	for _, content := range contents {
		log.Printf("  deleting %s\n", content.Key)
		deleteContentRaw(client, config, bucket, content.Key)
	}
}

func deleteBucketForce(bucket string) bool {
	cleanBucket(bucket)
	return deleteBucket(bucket)
}

func deleteBucket(bucket string) bool {
	ok, _ := accessBucket(bucket, "DELETE", 204)
	if ok {
		fmt.Printf("Delete bucket '%s' successuflly\n", bucket)
		return true
	}
	return false
}

func createBucket(bucket string) bool {
	ok, _ := accessBucket(bucket, "PUT", 200)
	if ok {
		fmt.Printf("Create bucket '%s' successuflly\n", bucket)
		return true
	}
	return false
}

type BucketContentQueryResult struct {
	Contents []ContentQueryResult `xml:"Contents"`
}

type ContentQueryResult struct {
	Key string
	LastModified string
	ETag string
	Size int
}

func listBucketContents(bucket string) []ContentQueryResult {
	ok, body := accessBucket(bucket, "GET", 200)
	if ok {
		fmt.Printf("'%s' bucket contents:\n", bucket)
		var query BucketContentQueryResult
		xml.Unmarshal([]byte(body), &query)
		return query.Contents
	}
	return make([]ContentQueryResult, 0)
}

func getAccessRight(bucket string) {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}

	client := createClient(config)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s.%s/?acl", bucket, config.Host), strings.NewReader(""))
	req.Header.Set("Host", fmt.Sprintf("http://%s.%s", bucket, config.Host))

	sign(req, config, "", "", fmt.Sprintf("/%s/?acl", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Print(res.Status)
		log.Print(string(body))
		log.Fatal(err)
	}
}

func makeGrantTag(user *RiakUser, permission string) string {
	return fmt.Sprintf(`<Grant>
				<Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
				<ID>%s</ID>
				<DisplayName>%s</DisplayName>
				</Grantee>
				<Permission>%s</Permission>
			</Grant>`, user.Id, user.Display_name, permission)
}

func addAccessRight(bucket, userName string) {
	foundUser := findUser(userName)
	if foundUser == nil {
		fmt.Printf("User %s is not found\n", userName)
		os.Exit(1)
	}
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}
	admin := loadAdmin(config)

	adminXML := fmt.Sprintf(`<Owner>
			<ID>%s</ID>
			<DisplayName>%s</DisplayName>
		</Owner>`, admin.Id, admin.Display_name)
	adminPermission := makeGrantTag(admin, "FULL_CONTROL")
	userReadPermission := makeGrantTag(foundUser, "READ")
	userWritePermission := makeGrantTag(foundUser, "WRITE")

	requestBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
	<AccessControlPolicy>
		%s
		<AccessControlList>
			%s
			%s
			%s
		</AccessControlList>
	</AccessControlPolicy>`, adminXML, adminPermission, userReadPermission, userWritePermission)
	client := createClient(config)

	req, _ := http.NewRequest("PUT", fmt.Sprintf("http://%s.%s/?acl", bucket, config.Host), strings.NewReader(requestBody))
	req.Header.Set("Host", fmt.Sprintf("http://%s.%s", bucket, config.Host))

	sign(req, config, "", "", fmt.Sprintf("/%s/?acl", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	if res.StatusCode != 200 {
		log.Fatalln("Set bucket %s's ACL failed.", bucket)
	} else {
		fmt.Printf(`Set bucket %s's ACL successfully.
	owner: %s (FULL_CONTROL)
	user : %s (READ/WRITE)
`, bucket, admin.Display_name, foundUser.Display_name)
	}
}

func main() {
	log.SetPrefix("riakcs-helper")

	if len(os.Args) == 1 {
		usage()
		os.Exit(1)
	}
	if os.Args[1] == "init" && len(os.Args) == 6 {
		writeConfig(os.Args[2], os.Args[3], os.Args[4], os.Args[5], "")
	} else if os.Args[1] == "init" && len(os.Args) == 7 {
		writeConfig(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
	} else if os.Args[1] == "create-user" && len(os.Args) == 4 {
		user := createUser(os.Args[2], os.Args[3])
		if user != nil {
			fmt.Println("Create user successuflly")
			dumpUser(user)
		}
	} else if os.Args[1] == "show-user" && len(os.Args) == 2 {
		var users RiakUsers = getAllUsers()
		sort.Sort(users)
		for _, user := range users {
			dumpUser(user)
			fmt.Println("")
		}
		fmt.Printf("total %d users\n", len(users))
	} else if os.Args[1] == "show-user" && len(os.Args) == 3 {
		user := findUser(os.Args[2])
		if user != nil {
			dumpUser(user)
		}
	} else if os.Args[1] == "issue-credential" && len(os.Args) == 3 {
		user := issueNewUserCredential(os.Args[2])
		if user != nil {
			dumpUser(user)
		}
	} else if os.Args[1] == "modify-user" && len(os.Args) == 5 {
		user := modifyUser(os.Args[2], os.Args[3], os.Args[4])
		if user != nil {
			fmt.Println("Modify Result:\n")
			dumpUser(user)
		}
	} else if os.Args[1] == "enable-user" && len(os.Args) == 3 {
		user := setEnableUser(os.Args[2], "enabled")
		if user != nil {
			fmt.Println("Modify Result:\n")
			dumpUser(user)
		}
	} else if os.Args[1] == "disable-user" && len(os.Args) == 3 {
		user := setEnableUser(os.Args[2], "disabled")
		if user != nil {
			fmt.Println("Modify Result:\n")
			dumpUser(user)
		}
	} else if os.Args[1] == "create-project" && len(os.Args) == 4 {
		if (createBucket(os.Args[2])) {
			user := createUser(os.Args[2], os.Args[3])
			if user != nil {
				fmt.Println("Create user successuflly")
				dumpUser(user)
				addAccessRight(os.Args[2], os.Args[2])
			}
		}
	} else if os.Args[1] == "create-bucket" && len(os.Args) == 3 {
		createBucket(os.Args[2])
	} else if os.Args[1] == "create-bucket" && len(os.Args) == 4 {
		if (createBucket(os.Args[2])) {
			addAccessRight(os.Args[2], os.Args[3])
		}
	} else if os.Args[1] == "clean-bucket" && len(os.Args) == 3 {
		cleanBucket(os.Args[2])
	} else if os.Args[1] == "delete-bucket" && len(os.Args) == 3 {
		deleteBucket(os.Args[2])
	} else if os.Args[1] == "delete-bucket" && len(os.Args) == 4 && os.Args[2] == "-f" {
		deleteBucketForce(os.Args[3])
	} else if os.Args[1] == "delete" && len(os.Args) == 4 {
		deleteContent(os.Args[2], os.Args[3])
	} else if os.Args[1] == "list" && len(os.Args) == 2 {
		listBuckets()
	} else if os.Args[1] == "list" && len(os.Args) == 3 {
		contents := listBucketContents(os.Args[2])
		if len(contents) == 0 {
			fmt.Println("	empty bucket")
		}
		for _, content := range contents {
			fmt.Printf("  %s : %d byte, modified at %s\n", content.Key, content.Size, content.LastModified)
		}
	} else if os.Args[1] == "set-acl" && len(os.Args) == 4 {
		addAccessRight(os.Args[2], os.Args[3])
	} else if os.Args[1] == "get-acl" && len(os.Args) == 3 {
		// debug command it just dump raw XML
		getAccessRight(os.Args[2])
	} else {
		usage()
		os.Exit(1)
	}
}
