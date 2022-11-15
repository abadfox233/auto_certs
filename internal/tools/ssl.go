package tools

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"auto_certs/internal/service/apisix"
)

var (

	// ErrorImportFile means the certificate is invalid
	ErrSSLCertificate = errors.New("invalid certificate")
	// ErrorSSLCertificateResolution means the SSL certificate decode failed
	ErrSSLCertificateResolution = errors.New("certificate resolution failed")
	// ErrorSSLKeyAndCert means the SSL key and SSL certificate don't match
	ErrSSLKeyAndCert = errors.New("key and cert don't match")
)

func ParseSSL(crt, key string) (*apisix.SSL, error) {
	if crt == "" || key == "" {
		return nil, ErrSSLCertificate
	}

	certDERBlock, _ := pem.Decode([]byte(crt))
	if certDERBlock == nil {
		return nil, ErrSSLCertificateResolution
	}
	// match
	_, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		return nil, ErrSSLKeyAndCert
	}

	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)

	if err != nil {
		return nil, ErrSSLCertificateResolution
	}

	ssl := apisix.SSL{}
	//domain
	snis := []string{}
	if x509Cert.DNSNames != nil && len(x509Cert.DNSNames) > 0 {
		snis = x509Cert.DNSNames
	} else if x509Cert.IPAddresses != nil && len(x509Cert.IPAddresses) > 0 {
		for _, ip := range x509Cert.IPAddresses {
			snis = append(snis, ip.String())
		}
	} else {
		if x509Cert.Subject.Names != nil && len(x509Cert.Subject.Names) > 1 {
			var attributeTypeNames = map[string]string{
				"2.5.4.6":  "C",
				"2.5.4.10": "O",
				"2.5.4.11": "OU",
				"2.5.4.3":  "CN",
				"2.5.4.5":  "SERIALNUMBER",
				"2.5.4.7":  "L",
				"2.5.4.8":  "ST",
				"2.5.4.9":  "STREET",
				"2.5.4.17": "POSTALCODE",
			}
			for _, tv := range x509Cert.Subject.Names {
				oidString := tv.Type.String()
				typeName, ok := attributeTypeNames[oidString]
				if ok && typeName == "CN" {
					valueString := fmt.Sprint(tv.Value)
					snis = append(snis, valueString)
				}
			}
		}
	}

	ssl.Snis = snis
	ssl.Key = key
	ssl.ValidityStart = x509Cert.NotBefore.Unix()
	ssl.ValidityEnd = x509Cert.NotAfter.Unix()
	ssl.Cert = crt

	return &ssl, nil
}
