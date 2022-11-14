package config

import (
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type AutoCertConfig struct {
	Account     AccountConfig `mapstructure:"account"`
	Domains     []string      `mapstructure:"domains"`
	DNSResolves []string      `mapstructure:"dnsResolves"`
	StorePath   string        `mapstructure:"storePath"`
	AccessKey   string        `mapstructure:"accessKey"`
	SecretKey   string        `mapstructure:"secretKey"`
	CADirURL   string        `mapstructure:"caDirUrl"`
}

type AccountConfig struct {
	Email   string `mapstructure:"email"`
	KeyType string `mapstructure:"keyType"`
}

func InitConfig(configPath string) *AutoCertConfig {
	config := &AutoCertConfig{}
	v := viper.New()
	v.SetConfigFile(configPath)
	// 读取配置
	err := v.ReadInConfig()
	if err != nil {
		panic(err)
	}
	// 赋值给结构体
	err = v.Unmarshal(config)
	if err != nil {
		panic(err)
	}
	// 更新配置
	v.WatchConfig()
	v.OnConfigChange(func(event fsnotify.Event) {
		err := v.ReadInConfig()
		if err != nil {
			log.Panicln("配置更新失败")
		}
		err = v.Unmarshal(config)
		if err != nil {
			log.Panicln("配置更新失败")
		}
	})
	return config
}
