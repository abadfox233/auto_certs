package main

import (
	"flag"

	"auto_certs/internal/config"
	"auto_certs/internal/service"
)

var configPath = ""

func init() {
	flag.StringVar(&configPath, "c", "", "config file path")
	flag.Parse()
}

func main() {

	configVal := config.InitConfig(configPath)
	account := service.NewUser(*configVal)
	legoService, err:= service.NewLegoService(*configVal, account, &service.LocalFileCertProcessor{})
	if err != nil {
		panic(err)
	}
	legoService.ProcessAfterObtain(configVal.Domains...)

}
