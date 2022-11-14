package service

import (
	"os"

	"github.com/go-acme/lego/v4/certificate"
)


type CertProcessor interface {

	Process(cert *certificate.Resource) error

}

type LocalFileCertProcessor struct {
}

func (p *LocalFileCertProcessor) Process(cert *certificate.Resource) error {
	certFile := "/root/project/auto_certs/store/" + cert.Domain + ".crt"
	keyFile := "/root/project/auto_certs/store/" + cert.Domain + ".key"
	err := os.WriteFile(certFile, []byte(cert.Certificate), 0644)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyFile, []byte(cert.PrivateKey), 0644)
	if err != nil {
		return err
	}
	return nil
}