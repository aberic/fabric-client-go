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

func obtain(configID string) *Config {
	return Configs[configID]
}

func set(init *config.ReqConfigInit) error {
	conf := &Config{}
	if err := conf.set(init); nil != err {
		return err
	}
	configID := strings.Join([]string{init.LeagueDomain, init.Org.Domain}, "-")
	lockConfig.Lock()
	Configs[configID] = conf
	lockConfig.Unlock()
	return nil
}
