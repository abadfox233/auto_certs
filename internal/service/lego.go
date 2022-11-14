package service

import (
	"log"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"auto_certs/internal/config"
)

var (
	CertKeyType = certcrypto.RSA2048
)

const (
	AliDNS = "alidns"
)

type LegoService struct {
	CADirURL string
	client   *lego.Client
	CertProcessor CertProcessor
}

func NewLegoService(config config.AutoCertConfig, account *LegoAccount, processor CertProcessor) (*LegoService, error) {
	service := &LegoService{
		CADirURL: config.CADirURL,
		CertProcessor: processor,
	}
	legoConfig := lego.NewConfig(account)
	legoConfig.CADirURL = config.CADirURL
	legoConfig.Certificate.KeyType = CertKeyType
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Printf("Could not create lego client: %v", err)
		return nil, err
	}
	service.client = client
	if config.SecretKey != "" && config.AccessKey != ""{
		os.Setenv("ALICLOUD_ACCESS_KEY", config.AccessKey)
		os.Setenv("ALICLOUD_SECRET_KEY", config.SecretKey)
	}
	provider, err := dns.NewDNSChallengeProviderByName(AliDNS)
	if err != nil {
		log.Printf("Could not create dns challenge provider: %v", err)
		return nil, err
	}
	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(true, dns01.AddRecursiveNameservers(config.DNSResolves)))
	if err != nil {
		log.Printf("Could not set dns challenge provider: %v", err)
		return nil, err
	}
	if account.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		log.Printf("Registering account for %s", account.Email)
		if err != nil {
			log.Printf("Could not register account: %v", err)
			return nil, err
		}
		account.Registration = reg
		accountFilePath := filepath.Join(config.StorePath, "account.json")
		err = account.Save(accountFilePath)
		if err != nil {
			log.Printf("Could not save account: %v", err)
			return nil, err
		}
		log.Printf("Account store state  path %s", accountFilePath)
	}
	return service, nil
}

func (legoService *LegoService) ProcessAfterObtain(domains ...string) error {
	certificates, err := legoService.Obtain(domains...)
	if err != nil {
		return err
	}
	return legoService.CertProcessor.Process(certificates)
}

func (legoService *LegoService) Obtain(domains ...string) (*certificate.Resource, error) {

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  false,
	}
	certificates, err := legoService.client.Certificate.Obtain(request)
	if err != nil {
		log.Printf("Could not obtain certificates: %v", err)
		return nil, err
	}

	return certificates, nil

}

