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

	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/writers"

	"github.com/Sirupsen/logrus"

	"github.com/asaskevich/govalidator"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "metadata_extractor",
	Short: "silly application that reads sysdig traces and get info",
	Long: `This silly application reads from sysdig traces from potted containers and extracts data from them. It has
	two functioning modes, one that process capture files from arguments and other that watches changes in filesystem through
	fanotify and process them	
	`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func loadConfig(cfg *config.GlobalConfig) {
	cfg.CfgWriters = viper.GetString("output")
	cfg.EShost = viper.GetString("elasticsearch_host")
	cfg.ESport = viper.GetString("elasticsearch_port")
	cfg.ProbeID = viper.GetString("probeid")
	cfg.SinkerAPIURL = viper.GetString("sinker_api_url")
	cfg.Follow = viper.GetBool("follow")
	cfg.Tracespath = viper.GetString("tracespath")
	cfg.Verbose = viper.GetBool("verbose")

	logrus.Debugf("[cmd.loadConfig] loaded config: %+v", cfg)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	if cfg.CfgWriters == "es" {
		if !govalidator.IsHost(cfg.EShost) {
			logrus.Fatal("invalid elasticsearch host")
		}
		if !govalidator.IsInt(cfg.ESport) {
			logrus.Fatal("invalid elasticsearch port")
		}
		es := writers.ElasticOutputClient{}
		cfg.Writer = &es
		es.SetURL(cfg.EShost, cfg.ESport)
		es.SetSniff(false)
		es.SetBulkSize(1)
		if err := es.Init(); err != nil {
			logrus.Fatalf("[cmd.root] Unable to initialize ES writer %s", err)
		}

	} else {
		cfg.Writer = &writers.CommandLineWriter{}
	}
	probe, err := config.GetProbe(*cfg)
	if err != nil {
		logrus.Fatalf("[cmd.root] Unable to retrieve Probe %s", err)
	}
	cfg.Probe = probe

	if cfg.Verbose {
		logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
		logrus.SetLevel(logrus.InfoLevel)
	}

}

func init() {

	cobra.OnInitialize(initConfig)

	var cfg *config.GlobalConfig
	cfg = &config.Config
	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVarP(&cfg.CfgFile, "config", "c", "", "config file (default is $PWD/.metadata_extractor.yaml and $HOME/.metadata_extractor.yaml)")
	RootCmd.PersistentFlags().StringVarP(&cfg.CfgWriters, "output", "o", "", "where to output between cli and es")
	RootCmd.PersistentFlags().StringVar(&cfg.EShost, "elasticsearch_host", "", "host to connect to elasticsearch")
	RootCmd.PersistentFlags().StringVar(&cfg.ESport, "elasticsearch_port", "", "port to connect to elasticsearch")
	RootCmd.PersistentFlags().StringVarP(&cfg.ProbeID, "probeid", "i", "", "probe id on sinkers API")
	RootCmd.PersistentFlags().StringVarP(&cfg.SinkerAPIURL, "sinker_api_url", "s", "http://main01.superprivyhosting.com:38080", "sinker_api_url")
	RootCmd.PersistentFlags().BoolVarP(&cfg.Follow, "follow", "f", false, "follow traces created on fs, needs -i parameter")
	RootCmd.PersistentFlags().StringVarP(&cfg.Tracespath, "tracebasepath", "d", "/var/log/traces", "Where the traces are stored ")
	RootCmd.PersistentFlags().StringVarP(&cfg.SyncBandwidthLimit, "bandwidthlimit", "b", "1024", "Amount of bandwidth in KiB used for syncing files")
	RootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "gives detailed logging")

	viper.BindPFlag("output", RootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("elasticsearch_host", RootCmd.PersistentFlags().Lookup("elasticsearch_host"))
	viper.BindPFlag("elasticsearch_port", RootCmd.PersistentFlags().Lookup("elasticsearch_port"))
	viper.BindPFlag("probeid", RootCmd.PersistentFlags().Lookup("probeid"))
	viper.BindPFlag("sinker_api_url", RootCmd.PersistentFlags().Lookup("sinker_api_url"))
	viper.BindPFlag("follow", RootCmd.PersistentFlags().Lookup("follow"))
	viper.BindPFlag("tracebasepath", RootCmd.PersistentFlags().Lookup("tracebasepath"))
	viper.BindPFlag("bandwidthlimit", RootCmd.PersistentFlags().Lookup("bandwidthlimit"))
	viper.BindPFlag("verbose", RootCmd.PersistentFlags().Lookup("verbose"))

	viper.SetDefault("follow", false)
	viper.SetDefault("verbose", false)

	viper.SetDefault("tracebasepath", "/var/log/traces")
	viper.SetDefault("sinker_api_url", "http://main01.superprivyhosting.com:38080")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var cfg *config.GlobalConfig
	cfg = &config.Config

	if cfg.CfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfg.CfgFile)
	}
	viper.SetConfigType("yaml")
	viper.SetConfigName(".metadata_extractor") // name of config file (without extension)
	viper.AddConfigPath(".")                   // adding current directory as first search path
	viper.AddConfigPath("$HOME")               // adding current directory as first search path
	viper.AutomaticEnv()                       // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		logrus.Error(err)
	} else {
		logrus.Debugf("[cmd.initConfig] Using config file:", viper.ConfigFileUsed())
	}
	loadConfig(cfg)

}
