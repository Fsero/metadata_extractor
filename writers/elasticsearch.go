package writers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"bitbucket.org/fseros/metadata_ssh_extractor/helpers"
	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	log "github.com/Sirupsen/logrus"
	"github.com/abh/geoip"
	"golang.org/x/sync/errgroup"
	elastic "gopkg.in/olivere/elastic.v5"
)

type attackerLoginAttemptDoc struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"@timestamp"`
	ContainerID string    `json:"containerid"`
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	Location    string    `json:"location"`
	User        string    `json:"user"`
	Password    string    `json:"password"`
	Successful  bool      `json:"successful"`
}

type attackerActivityDoc struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"@timestamp"`
	ContainerID string    `json:"containerid"`
	PID         string    `json:"pid"`
	User        string    `json:"user"`
	SourceFile  string    `json:"source"`
	Activity    string    `json:"activity"`
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
		log.Error(err)
	}
	log.Debugf("[createAttemptsIndex] index %s exists? %s", indexName, exists)

	if !exists {
		// Create a new index.
		mapping := `{
			"settings":{
				"number_of_shards":5,
				"number_of_replicas":1
			},
			"aliases" : {
				"ssh_login_attempts" : {}
			},
			"mappings": {
				"activity": {
					"dynamic": "strict",
					"properties": {
						"containerid": {
							"type": "string"
						},
						"id": {
							"type": "string"
						},
						"probe_provider": {
							"type": "string"
						},
						"probe_provider_location": {
							"type": "geo_point"
						},
						"probe_name": {
							"type": "string"
						},
						"probe_ip": {
							"type": "string"
						},
						"ip": {
							"type": "string"
						},
						"country": {
							"type": "string"
						},
						"location": {
							"type": "geo_point"
						},
						"@timestamp": {
						"type": "date",
							"format": "strict_date_optional_time||epoch_millis||epoch_second"
						},
						"city": {
							"type": "string"
						},
						"user": {
							"type": "string"
						},
						"password": {
							"type": "string"
						},
						"successful": {
							"type": "string"
						}
					}
			 }
		    }
		}`
		createIndex, err := e.client.CreateIndex(indexName).BodyString(mapping).Do(context.Background())
		if err != nil {
			// Handle error
			log.Error(err)
		}
		if !createIndex.Acknowledged {
			log.Error(err)

		}

	}
}

func (e ElasticOutputClient) createSSHActivitiesIndexIfnotExist(indexDate time.Time) {
	// Create an index
	indexName := fmt.Sprintf("ssh_activities-%d-%d", indexDate.Year(), indexDate.Month())
	exists, err := e.client.IndexExists(indexName).Do(context.Background())
	if err != nil {
		log.Error(err)
	}
	log.Debugf("[createSSHActivitiesIndexIfnotExist] index %s exists? %s", indexName, exists)

	if !exists {
		// Create a new index.

		mapping := `{
				"settings":{
					"number_of_shards":5,
					"number_of_replicas":1
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
								"type": "string"
							},
							"probe_ip": {
								"type": "string"
							},
							"id": {
								"type": "string"
							},
							"pid": {
								"type": "string"
							},
							"user": {
								"type": "string"
							},
							"@timestamp": {
								"type": "date",
								"format": "strict_date_optional_time||epoch_millis||epoch_second"
							},
							"source": {
								"type": "string"
							},
							"activity": {
								"type": "string"
							}
						}
			 		}
				}
			}
		}`
		createIndex, err := e.client.CreateIndex(indexName).BodyString(mapping).Do(context.Background())
		if err != nil {
			// Handle error
			log.Error(err)
		}
		if !createIndex.Acknowledged {
			log.Error(err)

		}

	}
}

func (e ElasticOutputClient) WriteAttackerActivies(activities []parsers.AttackerActivity) error {
	log.Debugf("[WriteAttackerActivies] ES activities %s", len(activities))
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
			d := attackerActivityDoc{
				ID:          id,
				Timestamp:   date,
				ContainerID: entry.ContainerID,
				PID:         entry.PID,
				SourceFile:  entry.SourceFile,
				User:        entry.User,
				Activity:    entry.Activity,
			}
			log.Debugf("%+v", entry)
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
			log.Debugf("%10d | %6d req/s | %02d:%02d\r", current, pps, sec/60, sec%60)

			// Enqueue the document
			log.Debugf("[WriteAttackerActivies] document to writre %s", d)
			bulk.Add(elastic.NewBulkIndexRequest().Id(d.ID).Doc(d))
			if bulk.NumberOfActions() >= e.bulkSize {
				// Commit
				res, err := bulk.Do(ctx)
				if err != nil {
					return err
				}
				if res.Errors {
					// Look up the failed documents with res.Failed(), and e.g. recommit
					log.Debugf("Bulk commit failed :%s", res.Items)

					for _, s := range res.Items {
						for k, v := range s {
							log.Debugf("Bulk commit failed %s %s", k, v)
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
		log.Fatal(err)
	}

	// Final results
	dur := time.Since(begin).Seconds()
	sec := int(dur)
	pps := int64(float64(total) / dur)
	log.Infof("Writing %10d documents in Elasticsearch | %6d req/s | %02d:%02d\n", total, pps, sec/60, sec%60)

	return nil
}

func (e ElasticOutputClient) WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt, geoIP *geoip.GeoIP) error {
	buf := make([]byte, 32)
	docsc := make(chan attackerLoginAttemptDoc)
	g, ctx := errgroup.WithContext(context.TODO())
	begin := time.Now()
	g.Go(func() error {
		defer close(docsc)

		for _, entry := range attempts {

			_, err := rand.Read(buf)
			if err != nil {
				return err
			}
			id := base64.URLEncoding.EncodeToString(buf)
			date, err := helpers.ParseUnixTimestamp(entry.UnixTime)
			if err != nil {
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
			d := attackerLoginAttemptDoc{
				ID:          id,
				Timestamp:   *date,
				ContainerID: entry.ContainerID,
				IP:          entry.IP,
				Location:    GeoLocation,
				Country:     Country,
				Successful:  entry.Successful,
				User:        entry.User,
				Password:    entry.Password,
			}
			log.Debugf("%+v", entry)
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
			bulk.Index(fmt.Sprintf("ssh_attempts-%d-%d", d.Timestamp.Year(), d.Timestamp.Month())).Type("attempt")
			// Simple progress
			current := atomic.AddUint64(&total, 1)
			dur := time.Since(begin).Seconds()
			sec := int(dur)
			pps := int64(float64(current) / dur)
			log.Debugf("%10d | %6d req/s | %02d:%02d\r", current, pps, sec/60, sec%60)

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
							log.Debugf("%s %s", k, v)
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
		log.Fatal(err)
	}

	// Final results
	dur := time.Since(begin).Seconds()
	sec := int(dur)
	pps := int64(float64(total) / dur)
	log.Infof("Writing %10d documents in Elasticsearch | %6d req/s | %02d:%02d\n", total, pps, sec/60, sec%60)

	return nil
}

func (e *ElasticOutputClient) Init() error {
	log.Debug("initialize elasticsearch output")
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
