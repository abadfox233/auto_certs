package service

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"auto_certs/internal/config"
)

const filePerm os.FileMode = 0o600

type LegoAccount struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (account *LegoAccount) GetEmail() string {
	return account.Email
}
func (account LegoAccount) GetRegistration() *registration.Resource {
	return account.Registration
}
func (account *LegoAccount) GetPrivateKey() crypto.PrivateKey {
	return account.key
}

// loadKeyFromDisk 从磁盘加载用户信息
func loadAccountFromDisk(accountFilePath string, email string, privateKey crypto.PrivateKey) (*LegoAccount, error) {

	fileBytes, err := os.ReadFile(accountFilePath)
	if err != nil {
		log.Printf("Could not load file for account %s: %v", email, err)
		return nil, err
	}
	u := &LegoAccount{Email: email, key: privateKey}
	err = json.Unmarshal(fileBytes, u)
	if err != nil {
		log.Printf("Could not parse file for account %s: %v", email, err)
		return nil, err
	}
	u.key = privateKey

	if u.Registration == nil || u.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(privateKey, "")
		if err != nil {
			log.Printf("Could not load account for %s. Registration is nil: %#v", email, err)
			return nil, err
		}
		u.Registration = reg
		err = u.Save(accountFilePath)
		if err != nil {
			log.Printf("Could not save account for %s. Registration is nil: %#v", email, err)
			return nil, err
		}
	}
	return u, nil
}

// Save 保存状态
func (account *LegoAccount) Save(accountFilePath string) error {
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(accountFilePath, jsonBytes, filePerm)
}

// tryRecoverRegistration 尝试从 ACME 服务器恢复用户状态
func tryRecoverRegistration(privateKey crypto.PrivateKey, caDirUrl string) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&LegoAccount{key: privateKey})
	config.CADirURL = caDirUrl
	config.UserAgent = fmt.Sprintf("%s lego-cli/%s", "xenolf-acme", "0.1")

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func NewUser(config config.AutoCertConfig) *LegoAccount {

	privateKey, err := loadKeyFromDisk(config)
	if err != nil {
		log.Fatalf("Could not load private key for %s: %#v", config.Account.Email, err)
	}
	return loadAccount(privateKey, config)
}

// getKeyType the type from which private keys should be generated.
func getKeyType(keyType string) certcrypto.KeyType {
	switch strings.ToUpper(keyType) {
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	case "RSA8192":
		return certcrypto.RSA8192
	case "EC256":
		return certcrypto.EC256
	case "EC384":
		return certcrypto.EC384
	}
	log.Fatalf("Unsupported KeyType: %s", keyType)
	return ""
}

// 生成私钥
func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	err = pem.Encode(certOut, pemKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// 加载私钥
func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func loadAccount(privateKey crypto.PrivateKey, config config.AutoCertConfig) *LegoAccount {
	accountFilePath := filepath.Join(config.StorePath, "account.json")
	if _, err := os.Stat(accountFilePath); err != nil {
		log.Printf("Could not load account for %s. File does not exist: %#v", config.Account.Email, err)
		return &LegoAccount{Email: config.Account.Email, key: privateKey}
	}
	user, err := loadAccountFromDisk(accountFilePath, config.Account.Email, privateKey)
	if err != nil {
		log.Printf("Could not load account for %s. File does not exist: %#v", config.Account.Email, err)
		return &LegoAccount{Email: config.Account.Email, key: privateKey}
	}
	return user
}

func loadKeyFromDisk(config config.AutoCertConfig) (crypto.PrivateKey, error) {
	// 加载私钥
	keyPath := filepath.Join(config.StorePath, config.Account.Email+".key")
	keyType := getKeyType(config.Account.KeyType)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Printf("No key found for account %s. Generating a %s key.", config.Account.Email, keyType)

		privateKey, err := generatePrivateKey(keyPath, keyType)
		if err != nil {
			log.Printf("Could not generate RSA private account key for account %s: %v", config.Account.Email, err)
			return nil, err
		}
		log.Printf("Saved key to %s", keyPath)
		return privateKey, nil
	}

	privateKey, err := loadPrivateKey(keyPath)
	if err != nil {
		log.Printf("Could not load RSA private key from file %s: %v", keyPath, err)
		return nil, err
	}
	return privateKey, nil

}
