package service

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-resty/resty/v2"

	"auto_certs/internal/service/apisix"
	"auto_certs/internal/tools"
)


type CertProcessor interface {
	Process(cert *certificate.Resource) error
}

type LocalFileCertProcessor struct {
	storePath string
}

func NewLocalFileProcessor(storePath string) *LocalFileCertProcessor {
	return &LocalFileCertProcessor{storePath: storePath}
}

func (p *LocalFileCertProcessor) Process(cert *certificate.Resource) error {
	certFile := filepath.Join(p.storePath, cert.Domain+".crt")
	keyFile := filepath.Join(p.storePath, cert.Domain+".key")
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

type ApiSixCertProcessor struct {
	sslUrl string
	client *resty.Client
}

func NewApiSixProcessor(sslUrl string, headers map[string]string) *ApiSixCertProcessor {
	client := resty.New()
	for k, v := range headers {
		client.SetHeader(k, v)
	}
	return &ApiSixCertProcessor{
		sslUrl: sslUrl,
		client: client,
	}
}

func (p *ApiSixCertProcessor) Process(cert *certificate.Resource) error {
	log.Printf("处理 cert: %s", cert.Domain)
	ssl, err := tools.ParseSSL(string(cert.Certificate), string(cert.PrivateKey))
	if err != nil {
		log.Printf("解析证书失败: %v", err)
		return err
	}
	r := p.client.NewRequest()
	rsp, err := r.Get(p.sslUrl)
	if err != nil {
		log.Printf("获取证书列表失败: %v", err)
		return err
	}
	apisixResponse := &apisix.ApiSixSSLResponse{}
	err = json.Unmarshal(rsp.Body(), &apisixResponse)
	if err != nil {
		log.Printf("解析证书列表失败: %v", err)
		return err
	}
	// 搜索旧证书
	oldIds := make([]string, 0)
	sslValue := apisixResponse.Nodes
	for _, nodeValue := range sslValue {
		if len(ssl.Snis) != len(nodeValue.Vale.Snis) {
			continue
		}
		sort.Strings(ssl.Snis)
		sort.Strings(nodeValue.Vale.Snis)
		sslSnis := strings.Join(ssl.Snis, ",")
		nodeSnis := strings.Join(nodeValue.Vale.Snis, ",")
		if sslSnis == nodeSnis {
			oldIds = append(oldIds, nodeValue.Vale.Id)
		}
	}
	// 更新证书
	if p.createApiSixSSL(ssl) != nil {
		return err
	}
	// 删除旧证书
	for _, id := range oldIds {
		deleteErr := p.deleteApiSixSSL(id)
		if deleteErr != nil {
			return deleteErr
		}
	}
	return nil
}

func (p *ApiSixCertProcessor)deleteApiSixSSL(id string) error {
	r := p.client.NewRequest()
	rsp, err := r.Delete(p.sslUrl + "/" + id)
	if err != nil {
		log.Printf("删除旧证书失败: %v", err)
		return err
	}
	if !rsp.IsSuccess() {
		log.Printf("删除旧证书失败: %v", rsp.String())
		return errors.New(rsp.String())
	}
	log.Printf("删除旧证书成功: %v", rsp.String())
	return nil
}

func (p *ApiSixCertProcessor)createApiSixSSL(ssl *apisix.SSL) error {
	r := p.client.NewRequest()
	r.SetBody(ssl)
	rsp, err := r.Post(p.sslUrl)
	if err != nil {
		log.Printf("创建证书失败: %+v", err)
		return err
	}
	if rsp.IsSuccess() {
		log.Printf("创建证书成功: %+v", rsp)
		return nil
	}
	log.Printf("创建证书失败: %+v", rsp)
	return errors.New("创建证书失败")
}
