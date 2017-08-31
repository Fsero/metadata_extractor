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
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"fmt"

	"strings"

	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/helpers"
	"bitbucket.org/fseros/metadata_extractor/parsers"
	"github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
	"github.com/rjeczalik/notify"
	"github.com/spf13/cobra"
)

func writeOutput(file string, geoIP *geoip.GeoIP, cfg *config.GlobalConfig) {
	var loginAttempts []parsers.AttackerLoginAttempt
	var activity []parsers.AttackerActivity

	loginAttempts = parsers.ExtractAttackerLoginAttempt(file)
	if loginAttempts != nil && len(loginAttempts) > 0 {
		cfg.Writer.WriteAttackerLoginAttempts(loginAttempts, geoIP, cfg)
	} else {
		logrus.Warningf("No login attempts found in %s maybe incomplete?, not traces found moving on", file)
	}
	activity = parsers.ExtractAttackerActivity(file)
	if activity != nil && len(activity) > 0 {
		cfg.Writer.WriteAttackerActivies(activity, cfg)
	} else {
		logrus.Warningf("No activities found in %s maybe incomplete?", file)
	}
}

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "extracts metadata from ssh potted containers",
	Long: `Extracts metadata from sysdig captures of ssh containers. 
	this process is extremely cpu intensive and fragile, do not try at home.`,
	Run: func(cmd *cobra.Command, args []string) {
		var geoIP *geoip.GeoIP

		var cfg *config.GlobalConfig
		cfg = &config.Config
		geoIP = helpers.InitializeGeoIP()
		if !parsers.Init() {
			logrus.Fatal("Unable to initialize ssh parser")
		}
		if !cfg.Follow {
			for _, f := range args {
				files, err := filepath.Glob(f)
				if err != nil {
					logrus.Fatalf("[cmd.SSH] invalid path %s", err)
					os.Exit(1)
				}
				for _, file := range files {
					writeOutput(file, geoIP, cfg)

					if _, err := os.Stat(file); os.IsNotExist(err) {
						logrus.Debugf(" %s does not exist", file)
						continue
					}
				}
			}
		} else {
			if cfg.ProbeID == "" {
				logrus.Fatalf("without a probeID its imposible to follow paths, set a valid probeID with -i")
			}
			g, ctx := errgroup.WithContext(context.TODO())
			// Make the channel buffered to ensure no event is dropped. Notify will drop
			// an event if the receiver is not able to keep up the sending pace.

			path := fmt.Sprintf("%s/%s/%s/", cfg.Tracespath, cfg.Probe.FQDN, cfg.Probe.IPv4)
			c := make(chan notify.EventInfo, 1)
			g.Go(func() error {
				// Set up a watchpoint listening for events within a directory tree rooted
				// at current working directory. Dispatch remove events to c.
				logrus.Infof("watching for new files in %s", path)
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
						if strings.Contains(event.Path(), fmt.Sprintf(".%s", cfg.Probe.FQDN)) {
							logrus.Debugf("partial file %s found skipping", event.Path())
							continue
						}
						logrus.Infof("new capture file found! processing %s", event.Path())
						logrus.Debugf("notify event %s", event.Path())
						// sometimes we receive the notification before the file has been written really due
						// to be in the cache. so we wait here one second to give time to hdd for flushing.
						writeOutput(event.Path(), geoIP, cfg)
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})

			if err := g.Wait(); err != nil {
				logrus.Fatalf("[cmd.sshCmd] unexpected error while processing ssh %s", err)
			}
		}

	},
}

func init() {
	RootCmd.AddCommand(sshCmd)
}
