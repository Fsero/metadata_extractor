// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sync/errgroup"

	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/helpers"

	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "sync files from ssh potted containers",
	Long:  `creates a directory and start syncing every X mins. do not try at home.`,
	Run: func(cmd *cobra.Command, args []string) {
		tickChan := time.NewTicker(time.Second * 5).C
		var cfg *config.GlobalConfig
		cfg = &config.Config
		logrus.Debugf("[cmd.fileCmd] creating path for storing traces %s %s %s", cfg.Probe.Tracespath, cfg.Probe.FQDN, cfg.Probe.IPv4)
		path := fmt.Sprintf("%s/%s/%s/", cfg.Probe.Tracespath, cfg.Probe.FQDN, cfg.Probe.IPv4)
		logrus.Debugf("[cmd.fileCmd] creating path for storing traces %s ", path)
		err := os.MkdirAll(path, 0755)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Cannot create path %s", err)
		}
		g, ctx := errgroup.WithContext(context.TODO())
		g.Go(func() error {
			for {
				select {
				case <-tickChan:
					fmt.Println("Ticker ticked")
					rsync := exec.Command("rsync", "-avzh", "-e", fmt.Sprintf("'ssh -p 30009 %s:%s*'", cfg.Probe.FQDN, cfg.Probe.FQDN), path)
					logrus.Debug(rsync)
					stdout, stderr, err := helpers.Pipeline(rsync)
					logrus.Debugf("OUT: %s , ERR: %s", stdout, stderr)
					if err != nil {
						logrus.Fatalf(" Error when tried to launch rsync %s", err)
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
		if err := g.Wait(); err != nil {
			logrus.Fatalf("Unexpected error while file sync %s ", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(fileCmd)
}
