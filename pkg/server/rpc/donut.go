/*
 * Minio Cloud Storage, (C) 2015 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpc

import (
	"net/http"

	"github.com/minio/minio/pkg/donut"
	"github.com/minio/minio/pkg/probe"
)

// DonutService donut service
type DonutService struct{}

// DonutArgs collections of disks and name to initialize donut
type DonutArgs struct {
	Name     string
	MaxSize  uint64
	Hostname string
	Disks    []string
}

// Reply reply for successful or failed Set operation
type Reply struct {
	Message string `json:"message"`
	Error   error  `json:"error"`
}

func setDonut(args *DonutArgs, reply *Reply) *probe.Error {
	conf := &donut.Config{Version: "0.0.1"}
	conf.DonutName = args.Name
	conf.MaxSize = args.MaxSize
	conf.NodeDiskMap = make(map[string][]string)
	conf.NodeDiskMap[args.Hostname] = args.Disks
	if err := donut.SaveConfig(conf); err != nil {
		return err.Trace()
	}
	reply.Message = "success"
	reply.Error = nil
	return nil
}

// Set method
func (s *DonutService) Set(r *http.Request, args *DonutArgs, reply *Reply) error {
	return setDonut(args, reply)
}
