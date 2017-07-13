package writers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"bitbucket.org/fseros/metadata_extractor/config"
	"bitbucket.org/fseros/metadata_extractor/helpers"
	"bitbucket.org/fseros/metadata_extractor/parsers"
	"github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
	"golang.org/x/sync/errgroup"
	elastic "gopkg.in/olivere/elastic.v5"
)

type attackerLoginAttemptDoc struct {
	ID            string           `json:"id"`
	Timestamp     time.Time        `json:"@timestamp"`
	ContainerID   string           `json:"containerid"`
	IP            string           `json:"ip"`
	Country       string           `json:"country"`
	Location      elastic.GeoPoint `json:"location"`
	User          string           `json:"user"`
	Password      string           `json:"password"`
	Successful    bool             `json:"successful"`
	ProbeIP       string           `json:"probe_ip"`
	ProbeName     string           `json:"probe_name"`
	ProbeProvider string           `json:"probe_provider"`
	ProbeLocation elastic.GeoPoint `json:"probe_provider_location"`
}

type attackerActivityDoc struct {
	ID            string           `json:"id"`
	Timestamp     time.Time        `json:"@timestamp"`
	ContainerID   string           `json:"containerid"`
	PID           string           `json:"pid"`
	User          string           `json:"user"`
	SourceFile    string           `json:"source"`
	Activity      string           `json:"activity"`
	ProbeIP       string           `json:"probe_ip"`
	ProbeName     string           `json:"probe_name"`
	ProbeProvider string           `json:"probe_provider"`
	ProbeLocation elastic.GeoPoint `json:"probe_provider_location"`
}

type ElasticOutputClient struct {
	client   *elastic.Client
	url      string
	sniff    bool
	n        int
	bulkSize int
}

func (e ElasticOutputClient) createAttemptsIndex(indexDate time.Time) {
	// Create an index
	indexName := fmt.Sprintf("ssh_login_attempts-%d-%d", indexDate.Year(), indexDate.Month())
	exists, err := e.client.IndexExists(indexName).Do(context.Background())
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Debugf("[createAttemptsIndex] index %s exists? %s", indexName, exists)

	if !exists {
		logrus.Info("[createAttemptsIndex] creating index")
		// Create a new index.
		mapping := `
{
			"settings":{
				"number_of_shards":5,
				"number_of_replicas":1,
				"index.mapper.dynamic":false
			},
			"aliases" : {
				"ssh_login_attempts" : {}
			},
			"mappings": {
				"attempt": {
					"properties": {
						"containerid": {
							"type": "keyword"
						},
						"id": {
							"type": "keyword"
						},
						"probe_provider": {
							"type": "keyword"
						},
						"probe_provider_location": {
							"type": "geo_point"
						},
						"probe_name": {
							"type": "keyword"
						},
						"probe_ip": {
							"type": "keyword"
						},
						"ip": {
							"type": "keyword"
						},
						"country": {
							"type": "keyword"
						},
						"location": {
							"type": "geo_point"
						},
						"@timestamp": {
						"type": "date",
							"format": "strict_date_optional_time||epoch_millis||epoch_second"
						},
						"city": {
							"type": "keyword"
						},
						"user": {
							"type": "keyword"
						},
						"password": {
							"type": "keyword"
						},
						"successful": {
							"type": "keyword"
						}
					}
			 }
		}
}
		`
		createIndex, err := e.client.CreateIndex(indexName).BodyString(mapping).Do(context.Background())
		if err != nil {
			// Handle error
			logrus.Fatal(err)
		}
		if !createIndex.Acknowledged {
			logrus.Fatal(err)

		}

	}
}

func (e ElasticOutputClient) createSSHActivitiesIndexIfnotExist(indexDate time.Time) {
	// Create an index
	indexName := fmt.Sprintf("ssh_activities-%d-%d", indexDate.Year(), indexDate.Month())
	exists, err := e.client.IndexExists(indexName).Do(context.Background())
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Debugf("[createSSHActivitiesIndexIfnotExist] index %s exists? %s", indexName, exists)

	if !exists {
		// Create a new index.

		mapping := `{
				"settings":{
					"number_of_shards":5,
					"number_of_replicas":1,
					"index.mapper.dynamic":false
				},
				"aliases" : {
						"ssh_activities" : {}
				},
				"mappings": {
					"activity": {
						"dynamic": "strict",
						"properties": {
							"containerid": {
								"type": "string"
							},
							"probe_provider": {
								"type": "string"
							},
							"probe_provider_location": {
								"type": "geo_point"
							},
							"probe_name": {
								"type": "keyword"
							},
							"probe_ip": {
								"type": "keyword"
							},
							"id": {
								"type": "keyword"
							},
							"pid": {
								"type": "keyword"
							},
							"user": {
								"type": "keyword"
							},
							"@timestamp": {
								"type": "date",
								"format": "strict_date_optional_time||epoch_millis||epoch_second"
							},
							"source": {
								"type": "keyword"
							},
							"activity": {
								"type": "keyword"
							}
						}
			 		}
				}
			}
		}`
		createIndex, err := e.client.CreateIndex(indexName).BodyString(mapping).Do(context.Background())
		if err != nil {
			// Handle error
			logrus.Fatal(err)
		}
		if !createIndex.Acknowledged {
			logrus.Fatal(err)

		}

	}
}

func (e ElasticOutputClient) WriteAttackerActivies(activities []parsers.AttackerActivity, cfg *config.GlobalConfig) error {
	logrus.Debugf("[WriteAttackerActivies] ES activities %s", len(activities))
	buf := make([]byte, 32)
	docsc := make(chan attackerActivityDoc)
	g, ctx := errgroup.WithContext(context.TODO())
	begin := time.Now()
	g.Go(func() error {
		defer close(docsc)

		for _, entry := range activities {

			_, err := rand.Read(buf)
			if err != nil {
				return err
			}
			id := base64.URLEncoding.EncodeToString(buf)
			date, err := time.Parse("2006-01-02 15:04:05.000000000", entry.Datetime)
			if err != nil {
				return err
			}
			var d attackerActivityDoc
			var probeip, probename, probeprovider string
			var probelocation *elastic.GeoPoint
			if cfg.Probe == nil {
				probeip = "UNKNOWN IP"
				probename = "UNKNOWN PROBE"
				probeprovider = "UNKNOWN PROVIDER"
				probelocation = &elastic.GeoPoint{}
			} else {
				probeip = cfg.Probe.IPv4
				probestringlocation := fmt.Sprintf("%s,%s", cfg.Probe.Geolatitude, cfg.Probe.Geolongitude)
				probename = cfg.Probe.FQDN
				probeprovider = cfg.Probe.Provider
				probelocation, err = elastic.GeoPointFromString(probestringlocation)
				if err != nil {
					logrus.Errorf("Unable to get geo point from %s %+v", probestringlocation, probelocation)
					probelocation = &elastic.GeoPoint{}

				}
				logrus.Infof("%s %+v", probestringlocation, probelocation)
			}
			d = attackerActivityDoc{
				ID:            id,
				Timestamp:     date,
				ContainerID:   entry.ContainerID,
				PID:           entry.PID,
				SourceFile:    entry.SourceFile,
				User:          entry.User,
				Activity:      entry.Activity,
				ProbeIP:       probeip,
				ProbeLocation: *probelocation,
				ProbeName:     probename,
				ProbeProvider: probeprovider,
			}
			logrus.Debugf("%+v", d)
			select {
			case docsc <- d:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil

	})

	// Second goroutine will consume the documents sent from the first and bulk insert into ES
	var total uint64
	g.Go(func() error {
		bulk := e.client.Bulk()
		for d := range docsc {
			e.createSSHActivitiesIndexIfnotExist(d.Timestamp)
			bulk.Index(fmt.Sprintf("ssh_activities-%d-%d", d.Timestamp.Year(), d.Timestamp.Month())).Type("activity")
			// Simple progress
			current := atomic.AddUint64(&total, 1)
			dur := time.Since(begin).Seconds()
			sec := int(dur)
			pps := int64(float64(current) / dur)
			logrus.Debugf("%10d | %6d req/s | %02d:%02d\r", current, pps, sec/60, sec%60)

			// Enqueue the document
			logrus.Debugf("[WriteAttackerActivies] document to writre %s", d)
			bulk.Add(elastic.NewBulkIndexRequest().Id(d.ID).Doc(d))
			if bulk.NumberOfActions() >= e.bulkSize {
				// Commit
				res, err := bulk.Do(ctx)
				if err != nil {
					return err
				}
				if res.Errors {
					// Look up the failed documents with res.Failed(), and e.g. recommit
					logrus.Debugf("Bulk commit failed :%s", res.Items)

					for _, s := range res.Items {
						for k, v := range s {
							logrus.Debugf("Bulk commit failed %s %s", k, v)
						}
					}
					return errors.New("bulk commit failed")
				}
				// "bulk" is reset after Do, so you can reuse it
			}

			select {
			default:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Commit the final batch before exiting
		if bulk.NumberOfActions() > 0 {
			_, err := bulk.Do(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	})

	// Wait until all goroutines are finished
	if err := g.Wait(); err != nil {
		logrus.Fatal(err)
	}

	// Final results
	dur := time.Since(begin).Seconds()
	sec := int(dur)
	pps := int64(float64(total) / dur)
	logrus.Infof("Writing %10d documents in Elasticsearch | %6d req/s | %02d:%02d\n", total, pps, sec/60, sec%60)

	return nil
}

func (e ElasticOutputClient) WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP, cfg *config.GlobalConfig) error {
	buf := make([]byte, 32)
	docsc := make(chan attackerLoginAttemptDoc)
	g, ctx := errgroup.WithContext(context.TODO())
	begin := time.Now()
	g.Go(func() error {
		defer close(docsc)

		for _, entry := range attempts {
			logrus.Debugf("[WriteAttackerLoginAttempts] %+v", entry)
			_, err := rand.Read(buf)
			if err != nil {
				logrus.Fatalf("[WriteAttackerLoginAttempts:elasticsearch] cannot ger random data to generate ES ID! %s", err)
				return err
			}
			id := base64.URLEncoding.EncodeToString(buf)

			date, err := helpers.ParseUnixTimestamp(entry.UnixTime)
			if err != nil {
				logrus.Fatalf("[WriteAttackerLoginAttempts:elasticsearch] Invalid UnixTime! %s", err)
				return err
			}

			record := geoIP.GetRecord(entry.IP)
			var GeoLocation, Country string
			if record != nil {
				GeoLatitude := fmt.Sprintf("%f", record.Latitude)
				GeoLongitude := fmt.Sprintf("%f", record.Longitude)
				Country = record.CountryName
				GeoLocation = fmt.Sprintf("%s,%s", GeoLatitude, GeoLongitude)
			} else {
				GeoLocation, Country = "", ""
			}
			var d attackerLoginAttemptDoc
			var probeip, probename, probeprovider string
			var probelocation *elastic.GeoPoint
			if cfg.Probe == nil {
				probeip = "UNKNOWN IP"
				probename = "UNKNOWN PROBE"
				probeprovider = "UNKNOWN PROVIDER"
				probelocation = &elastic.GeoPoint{}
			} else {
				probeip = cfg.Probe.IPv4
				probestringlocation := fmt.Sprintf("%s,%s", cfg.Probe.Geolatitude, cfg.Probe.Geolongitude)
				probename = cfg.Probe.FQDN
				probeprovider = cfg.Probe.Provider
				probelocation, err = elastic.GeoPointFromString(probestringlocation)
				if err != nil {
					logrus.Errorf("Unable to get geo point from %s %+v", probestringlocation, probelocation)
					probelocation = &elastic.GeoPoint{}
				}

				logrus.Debugf("location %s GeoPoint %+v", probestringlocation, probelocation)

			}
			location, err := elastic.GeoPointFromString(GeoLocation)
			if err != nil {
				logrus.Errorf("Unable to get geo point from %s %+v", GeoLocation, location)
				location = &elastic.GeoPoint{}

			}
			logrus.Debugf("location %s GeoPoint %+v", GeoLocation, location)

			d = attackerLoginAttemptDoc{
				ID:            id,
				Timestamp:     *date,
				ContainerID:   entry.ContainerID,
				IP:            entry.IP,
				Location:      *location,
				Country:       Country,
				Successful:    entry.Successful,
				User:          entry.User,
				Password:      entry.Password,
				ProbeIP:       probeip,
				ProbeLocation: *probelocation,
				ProbeName:     probename,
				ProbeProvider: probeprovider,
			}
			logrus.Debugf("%+v", d)
			select {
			case docsc <- d:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil

	})

	// Second goroutine will consume the documents sent from the first and bulk insert into ES
	var total uint64
	g.Go(func() error {
		bulk := e.client.Bulk()
		for d := range docsc {
			e.createAttemptsIndex(d.Timestamp)

			bulk.Index(fmt.Sprintf("ssh_login_attempts-%d-%d", d.Timestamp.Year(), d.Timestamp.Month())).Type("attempt")
			// Simple progress
			current := atomic.AddUint64(&total, 1)
			dur := time.Since(begin).Seconds()
			sec := int(dur)
			pps := int64(float64(current) / dur)
			logrus.Debugf("%10d | %6d req/s | %02d:%02d\r", current, pps, sec/60, sec%60)

			// Enqueue the document
			bulk.Add(elastic.NewBulkIndexRequest().Id(d.ID).Doc(d))
			if bulk.NumberOfActions() >= e.bulkSize {
				// Commit
				res, err := bulk.Do(ctx)
				if err != nil {
					return err
				}
				if res.Errors {
					// Look up the failed documents with res.Failed(), and e.g. recommit

					for _, s := range res.Items {
						for k, v := range s {
							logrus.Debugf("%s %s", k, v)
						}
					}
					return errors.New("bulk commit failed")
				}
				// "bulk" is reset after Do, so you can reuse it
			}

			select {
			default:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Commit the final batch before exiting
		if bulk.NumberOfActions() > 0 {
			_, err := bulk.Do(ctx)
			if err != nil {
				return err
			}
		}
		return nil
	})

	// Wait until all goroutines are finished
	if err := g.Wait(); err != nil {
		logrus.Fatal(err)
	}

	// Final results
	dur := time.Since(begin).Seconds()
	sec := int(dur)
	pps := int64(float64(total) / dur)
	logrus.Infof("Writing %10d documents in Elasticsearch | %6d req/s | %02d:%02d\n", total, pps, sec/60, sec%60)

	return nil
}

func (e *ElasticOutputClient) Init() error {
	logrus.Debug("initialize elasticsearch output")
	client, err := elastic.NewClient(elastic.SetURL(e.url), elastic.SetSniff(e.sniff))
	if err != nil {
		return err
	}
	e.client = client
	return nil
}

func (e *ElasticOutputClient) SetURL(host string, port string) {
	e.url = fmt.Sprintf("http://%s:%s", host, port)
}

func (e *ElasticOutputClient) SetSniff(sniff bool)  { e.sniff = sniff }
func (e *ElasticOutputClient) SetBulkSize(size int) { e.n = size; e.bulkSize = size }
