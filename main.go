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
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"mime"
	"mime/multipart"
	"net/http"
)

var b64 = base64.StdEncoding

const usageStr = `Usage:

Config:
	riakcs-helper init [url] [adminAccessKey] [adminSecretKey]

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
	riakcs-helper add-access [bucketName] [accesibleUserName]
		: Create bucket. If user name is passed,
		: give read/write access to specified user (owner is admin)

User and Bucket Operations:
	riakcs-helper create-project [bucketAndUserName] [email]
	    : Create user and bucket (both have same name)
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

type Config struct {
	AdminAccessKey string
	AdminSecretKey string
	Host string
}

func readConfig() *Config {
	usr, _ := user.Current()
	path := filepath.Join(usr.HomeDir, ".riakcs_helper")
	in, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	body, err := ioutil.ReadAll(in)
	in.Close()
	if err != nil {
		log.Fatal(err)
		return nil
	}
	config := Config{}
	err = json.Unmarshal(body, &config)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return &config
}

func writeConfig(host, adminAccessKey, adminSecretKey string) {
	usr, _ := user.Current()
	path := filepath.Join(usr.HomeDir, ".riakcs_helper")
	config := Config{adminAccessKey, adminSecretKey, host}
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

func sign(req *http.Request, config *Config, md5, contentType string) {
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
	str_to_sign := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", req.Method, md5, contentType, dateStr, req.URL.Path)
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
	url := fmt.Sprintf("%s/riak-cs/user", host)
	requestBody := fmt.Sprintf("{\"email\":\"%s\",\"name\":\"%s\"}", email, name)
	client := &http.Client{}
	req, _ := http.NewRequest("POST", url, strings.NewReader(requestBody))

	sign(req, config, "", "application/json")

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	if res.StatusCode != 201 {
		log.Fatalln("User creation failed.")
		return nil
	}
	var user RiakUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
		return nil
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

func findAdminAndUser(name string) (*RiakUser, *RiakUser) {
	users := getAllUsers()
	config := readConfig()

	var admin *RiakUser = nil
	var foundUser *RiakUser = nil
	for _, user := range users {
		if user.Name == name {
			foundUser = user
		} else if config.AdminAccessKey == user.Key_id {
			admin = user
		}
	}
	return admin, foundUser
}

func getAllUsers() []*RiakUser {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}
	url := fmt.Sprintf("%s/riak-cs/users",  config.Host)
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)

	sign(req, config, "", "application/json")

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	if err != nil {
		log.Fatal(err)
		return nil
	}
	if res.StatusCode != 200 {
		log.Fatalln("User creation failed.")
		return nil
	}

	mediaType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal(nil)
		return nil
	}
	if mediaType != "multipart/mixed" {
		log.Fatal("unknown return type. this code assumes multipart/mixed")
		return nil
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
			return nil
		}
		var users []RiakUser
		body, err := ioutil.ReadAll(part)
		if err != nil {
			log.Fatal(err)
			return nil
		}
		err = json.Unmarshal(body, &users)
		if err != nil {
			log.Fatal(err)
			return nil
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

	url := fmt.Sprintf("%s/riak-cs/user/%s", config.Host, foundUser.Key_id)

	client := &http.Client{}
	req, _ := http.NewRequest("PUT", url, strings.NewReader(requestBody))

	sign(req, config, "", "application/json")

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	var user RiakUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
		return nil
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

func createBucket(bucket string) {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}

	client := &http.Client{}
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/%s", config.Host, bucket), strings.NewReader(""))

	sign(req, config, "", "")

	req.Header.Set("Host", fmt.Sprintf("%s.s3.amazonaws.com", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Print(res.Status)
	log.Print(string(body))

	if res.StatusCode != 201 {
		log.Fatalln("Bucket creation failed.")
	}
}

func getAccessRight(bucket string) {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s?acl", config.Host, bucket), strings.NewReader(""))

	sign(req, config, "", "")

	req.Header.Set("Host", fmt.Sprintf("%s.s3.amazonaws.com", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Print(res.Status)
	log.Print(string(body))
}


func addAccessRight(bucket, userName string) {
	log.Print(bucket, userName)
	/*admin, foundUser := findAdminAndUser(userName)
	if foundUser == nil {
		fmt.Printf("User %s is not found\n", userName)
		return
	}

	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}

	client := &http.Client{}
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/%s?acl", config.Host, bucket), strings.NewReader())

	sign(req, config, "", "")

	req.Header.Set("Host", fmt.Sprintf("%s.s3.amazonaws.com", bucket))

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Print(res.Status)
	log.Print(string(body))

	if res.StatusCode != 201 {
		log.Fatalln("Bucket creation failed.")
	}*/
}

func createProject(email, bucket string) {
	config := readConfig()
	if config == nil {
		fmt.Println("Can't read config file. Call init command first.")
	}
	user := createUser(email, bucket)
	if user == nil {
		log.Fatalln("User creation error")
	}
	url := fmt.Sprintf("%s/buckets/%s", config.Host, bucket)
	client := &http.Client{}
	req, _ := http.NewRequest("PUT", url, strings.NewReader(""))

	sign(req, config, "", "application/json")

	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-amz-acl", "bucket-owner-full-control")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return
	}
	if res.StatusCode != 201 {
		log.Fatalln("Bucket creation failed.")
	}
}

func main() {
	log.SetPrefix("riakcs-helper")

	if len(os.Args) == 1 {
		usage()
		os.Exit(1)
	}
	if os.Args[1] == "init" && len(os.Args) == 5 {
		writeConfig(os.Args[2], os.Args[3], os.Args[4])
	} else if os.Args[1] == "create-user" && len(os.Args) == 4 {
		user := createUser(os.Args[2], os.Args[3])
		if user != nil {
			dumpUser(user)
		}
	} else if os.Args[1] == "show-user" && len(os.Args) == 2 {
		users := getAllUsers()
		for _, user := range users {
			dumpUser(user)
			fmt.Println("")
		}
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
		createProject(os.Args[2], os.Args[3])
	} else if os.Args[1] == "create-bucket" && len(os.Args) == 3 {
		createBucket(os.Args[2])
	} else if os.Args[1] == "add-access" && len(os.Args) == 4 {
		addAccessRight(os.Args[2], os.Args[3])
	} else if os.Args[1] == "get-access" && len(os.Args) == 3 {
		getAccessRight(os.Args[2])
	} else {
		usage()
		os.Exit(1)
	}
}
