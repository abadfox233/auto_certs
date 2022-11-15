package main

import (
	"flag"
	"log"

	"auto_certs/internal/config"
	"auto_certs/internal/resource"
	"auto_certs/internal/service"
)

var configPath = ""

func init() {
	flag.StringVar(&configPath, "c", "", "config file path")
	flag.Parse()
}

func main() {

	configVal := config.InitConfig(configPath)
	resource.AutoCertConfig = configVal
	account := service.NewUser(*configVal)
	localFileProcessor := service.NewLocalFileProcessor(configVal.StorePath)
	legoService, err := service.NewLegoService(*configVal, account)
	if err != nil {
		panic(err)
	}
	certResources, obtainErr := legoService.Obtain(configVal.Domains...)
	if obtainErr != nil {
		log.Fatalf("Error obtaining certificate: %v", obtainErr)
	}
	processErr := localFileProcessor.Process(certResources)
	if processErr != nil {
		log.Fatalf("process error: %v", processErr)
	}
	for _, apisixConfig := range configVal.ApiSix {
		apisixProcess := service.NewApiSixProcessor(apisixConfig.Url, apisixConfig.Headers)
		apiSixProcessErr := apisixProcess.Process(certResources)
		if apiSixProcessErr != nil {
			log.Printf("apisix process error: %v", apiSixProcessErr)
		}
	}
}
