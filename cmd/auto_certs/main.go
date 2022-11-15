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
	r, obtainErr := legoService.Obtain(configVal.Domains...)
	if obtainErr != nil {
		log.Fatalf("Error obtaining certificate: %v", obtainErr)
	}
	process := localFileProcessor.Process(r)
	if process != nil {
		log.Fatalf("process error: %v", process)
	}
}
