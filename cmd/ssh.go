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
	"fmt"
	"os"

	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sshCmd represents the ssh command
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "extracts metadata from ssh potted containers",
	Long: `Extracts metadata from sysdig captures of ssh containers. 
	this process is extremely cpu intensive and fragile, do not try at home.`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Work your own magic here
		fmt.Println("ssh called")
		fmt.Printf("%+v", args)
		var loginAttempts []parsers.AttackerLoginAttempt
		var activity []parsers.AttackerActivity

		if !parsers.Init() {
			log.Fatal("Unable to initialize ssh parser")
		}
		for _, f := range args {
			if _, err := os.Stat(f); os.IsNotExist(err) {
				log.Debugf(" %s does not exist", f)
				continue
			}
			loginAttempts = parsers.ExtractAttackerLoginAttempt(f)
			activity = parsers.ExtractAttackerActivity(f)
		}
		cfg.writer.WriteAttackerActivies(activity)
		cfg.writer.WriteAttackerLoginAttempts(loginAttempts)

	},
}

func init() {
	RootCmd.AddCommand(sshCmd)
}
