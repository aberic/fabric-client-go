/*
 * Copyright (c) 2019. Aberic - All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"encoding/json"
	"errors"
	"github.com/aberic/fabric-client-go/grpc/proto/config"
	"strings"
	"sync"
)

var (
	Configs    map[string]*Config
	lockConfig sync.RWMutex
)

func init() {
	Configs = map[string]*Config{}
}

func setConfig(req *config.ReqConfigSet) (resp *config.RespConfigSet, err error) {
	conf := &Config{}
	if resp, err = conf.set(req); nil != err {
		return &config.RespConfigSet{Code: config.Code_Fail, ErrMsg: err.Error()}, err
	}
	Set(req.LeagueDomain, req.Org.Domain, conf)
	return &config.RespConfigSet{Code: config.Code_Success}, nil
}

func obtainConfig(req *config.ReqConfigObtain) (resp *config.RespConfigObtain, err error) {
	var (
		conf        *Config
		configBytes []byte
	)
	if conf, err = Obtain(req.LeagueDomain, req.OrgDomain); nil != err {
		return &config.RespConfigObtain{Code: config.Code_Fail, ErrMsg: err.Error()}, err
	}
	if configBytes, err = json.Marshal(conf); nil != err {
		return &config.RespConfigObtain{Code: config.Code_Fail, ErrMsg: err.Error()}, err
	}
	return &config.RespConfigObtain{Code: config.Code_Success, ConfigBytes: configBytes}, nil
}

func listConfig(_ *config.ReqConfigList) (resp *config.RespConfigList, err error) {
	var orgConfigs []*config.OrgConfig
	lockConfig.Lock()
	for configID := range Configs {
		configIDSplits := strings.Split(configID, "-")
		orgConfigs = append(orgConfigs, &config.OrgConfig{LeagueDomain: configIDSplits[0], OrgDomain: configIDSplits[1]})
	}
	lockConfig.Unlock()
	return &config.RespConfigList{Code: config.Code_Success, Configs: orgConfigs}, nil
}

func deleteConfig(req *config.ReqConfigDelete) (resp *config.RespConfigDelete, err error) {
	lockConfig.Lock()
	for configID := range Configs {
		configIDSplits := strings.Split(configID, "-")
		for _, orgConfig := range req.Configs {
			if orgConfig.LeagueDomain == configIDSplits[0] && orgConfig.OrgDomain == configIDSplits[1] {
				delete(Configs, configID)
			}
		}
	}
	lockConfig.Unlock()
	return &config.RespConfigDelete{Code: config.Code_Success}, nil
}

func Obtain(leagueDomain, orgDomain string) (*Config, error) {
	conf, ok := Configs[obtainConfigID(leagueDomain, orgDomain)]
	if ok {
		return conf, nil
	}
	return nil, errors.New("config doesn't exist")
}

func Mock(req *config.ReqConfigSet) (*Config, error) {
	conf := &Config{}
	if _, err := conf.padding(req); nil != err {
		return nil, err
	}
	return conf, nil
}

func Set(leagueDomain, orgDomain string, conf *Config) {
	lockConfig.Lock()
	Configs[obtainConfigID(leagueDomain, orgDomain)] = conf
	lockConfig.Unlock()
}

func obtainConfigID(leagueDomain, orgDomain string) string {
	return strings.Join([]string{leagueDomain, orgDomain}, "-")
}
