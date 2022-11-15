package apisix

type ApiSixSSLResponse struct {
	ApiSixSSLNodeResponse `json:"node"`
	Action string `json:"action"`
	Count int `json:"count"`
}

type ApiSixSSLNodeResponse struct {
	Key string `json:"key"`
	Dir bool `json:"dir"`
	Nodes []ApiSixSSLNodeValue `json:"nodes"`
}

type ApiSixSSLNodeValue struct {

	CreatedIndex int `json:"createdIndex"`
	ModifiedIndex int `json:"modifiedIndex"`
	Key string `json:"key"`
	Vale ApiSixSSLModel `json:"value"`

}

type ApiSixSSLModel struct {
	Status int `json:"status"`
	Key string `json:"key"`
	Snis []string `json:"snis"`
	CreateTime int64 `json:"create_time"`
	Cert string `json:"cert"`
	UpdateTime int64 `json:"update_time"`
	Id string `json:"id"`
}

type SSL struct {
	Cert          string            `json:"cert,omitempty"`
	Key           string            `json:"key,omitempty"`
	Sni           string            `json:"sni,omitempty"`
	Snis          []string          `json:"snis,omitempty"`
	Certs         []string          `json:"certs,omitempty"`
	Keys          []string          `json:"keys,omitempty"`
	ExpTime       int64             `json:"exptime,omitempty"`
	Status        int               `json:"status"`
	ValidityStart int64             `json:"validity_start,omitempty"`
	ValidityEnd   int64             `json:"validity_end,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
}