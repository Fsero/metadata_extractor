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
	"io/ioutil"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/helpers"

	"os"

	"encoding/base64"

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
		_, err = exec.Command("/usr/bin/rsync", "-h").Output()
		if err != nil {
			logrus.Fatalf("Unable to sync cant find rsync in path %s", err)
		}
		if cfg.Probe.SSHprivatekey == "" && cfg.Probe.SSHprivatekey == "" {
			logrus.Fatalf("We need a SSH Key for sync :(")
		}
		err = os.Mkdir("/root/.ssh", 0700)
		logrus.Debug("[cmd.fileCmd] created dir /root/.ssh")

		if err != nil {
			logrus.Warningf("[cmd.fileCmd] ssh folder already exists %s", err)
		}
		var b []byte
		b, err = base64.URLEncoding.DecodeString(cfg.Probe.SSHprivatekey)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Unable to decode SSH private key :( %s", err)
		}
		logrus.Debug("[cmd.fileCmd] writed /root/.ssh/id_rsa")
		err = ioutil.WriteFile("/root/.ssh/id_rsa", b, 0400)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Unable to write SSH private key :( %s", err)
		}
		b, err = base64.URLEncoding.DecodeString(cfg.Probe.SSHpublickey)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Unable to decode SSH public key :( %s", err)
		}

		err = ioutil.WriteFile("/root/.ssh/id_rsa.pub", b, 0400)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Unable to write SSH public key :( %s", err)
		}
		sshConfig := fmt.Sprintf("Host %s\nUserKnownHostsFile /dev/null\nStrictHostKeyChecking no\nPort %d", cfg.Probe.FQDN, 30009)
		err = ioutil.WriteFile("/root/.ssh/config", []byte(sshConfig), 0400)
		if err != nil {
			logrus.Fatalf("[cmd.fileCmd] Unable to write SSH config :( %s", err)
		}

		g, ctx := errgroup.WithContext(context.TODO())
		g.Go(func() error {
			for {
				select {
				case <-tickChan:
					args := append([]string{}, `--bwlimit=1024`, `-avzh`, fmt.Sprintf(`file@%s:%s*`, cfg.Probe.FQDN, cfg.Probe.FQDN), fmt.Sprintf(`%s`, path))
					logrus.Debugf(strings.Join(args[:], " "))

					rsync := exec.Command("/usr/bin/rsync", args...)
					logrus.Debugf("CMD %s ARGS %s ENV %s", rsync.Process, rsync.Args, rsync.Env)
					stdout, stderr, err := helpers.Pipeline(rsync)
					logrus.Debugf("STDOUT: %s, STDERR: %s, ", stdout, stderr)
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
