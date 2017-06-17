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
	"os"

	"golang.org/x/sync/errgroup"

	"fmt"

	"bitbucket.org/fseros/metadata_ssh_extractor/helpers"
	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	log "github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
	"github.com/rjeczalik/notify"
	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "extracts metadata from ssh potted containers",
	Long: `Extracts metadata from sysdig captures of ssh containers. 
	this process is extremely cpu intensive and fragile, do not try at home.`,
	Run: func(cmd *cobra.Command, args []string) {
		var loginAttempts []parsers.AttackerLoginAttempt
		var activity []parsers.AttackerActivity
		var geoIP *geoip.GeoIP
		geoIP = helpers.InitializeGeoIP()
		if !parsers.Init() {
			log.Fatal("Unable to initialize ssh parser")
		}
		if !cfg.follow {
			for _, f := range args {
				if _, err := os.Stat(f); os.IsNotExist(err) {
					log.Debugf(" %s does not exist", f)
					continue
				}
				loginAttempts = parsers.ExtractAttackerLoginAttempt(f)
				activity = parsers.ExtractAttackerActivity(f)
				cfg.writer.WriteAttackerActivies(activity)
				cfg.writer.WriteAttackerLoginAttempts(loginAttempts, geoIP)
			}
		} else {
			if cfg.probeID == "" {
				log.Fatalf("without a probeID its imposible to follow paths, set a valid probeID with -i")
			}
			g, ctx := errgroup.WithContext(context.TODO())
			// Make the channel buffered to ensure no event is dropped. Notify will drop
			// an event if the receiver is not able to keep up the sending pace.

			path := fmt.Sprintf("%s/%s/%s/", cfg.tracespath, cfg.probe.FQDN, cfg.probe.IPv4)
			c := make(chan notify.EventInfo, 1)
			g.Go(func() error {
				// Set up a watchpoint listening for events within a directory tree rooted
				// at current working directory. Dispatch remove events to c.
				log.Infof("watching for new files in %s", path)
				if err := notify.Watch(path, c, notify.Create); err != nil {
					return err
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				}
			})

			g.Go(func() error {
				for event := range c {
					select {
					default:
						log.Infof("new capture file found! processing %s", event.Path())
						log.Debugf("notify event %s", event.Path())
						loginAttempts = parsers.ExtractAttackerLoginAttempt(event.Path())
						activity = parsers.ExtractAttackerActivity(event.Path())
						cfg.writer.WriteAttackerActivies(activity)
						cfg.writer.WriteAttackerLoginAttempts(loginAttempts, geoIP)
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})

			if err := g.Wait(); err != nil {
				log.Fatal(err)
			}
		}

	},
}

func init() {
	RootCmd.AddCommand(sshCmd)
}
