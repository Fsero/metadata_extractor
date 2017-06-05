package writers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"bitbucket.org/fseros/metadata_ssh_extractor/parsers"
	log "github.com/Sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	elastic "gopkg.in/olivere/elastic.v5"
)

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

func (e ElasticOutputClient) createAttemptsIndex() {
	// Create an index
	log.Info(e.client)
	exists, err := e.client.IndexExists("ssh_attempts").Do(context.Background())
	if err != nil {
		log.Error(err)
	}
	log.Info(exists)

	if !exists {
		// Create a new index.

		mapping := `{
		    "settings":{
			 "number_of_shards":5,
			 "number_of_replicas":1
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
		}`
		createIndex, err := e.client.CreateIndex("ssh_attempts").BodyString(mapping).Do(context.Background())
		if err != nil {
			// Handle error
			log.Error(err)
		}
		if !createIndex.Acknowledged {
			log.Error(err)

		}

	}
}

func (e ElasticOutputClient) createSSHActivitiesIndexIfnotExist() {
	// Create an index
	log.Info(e.client)
	exists, err := e.client.IndexExists("ssh_activities").Do(context.Background())
	if err != nil {
		log.Error(err)
	}
	log.Info(exists)

	if !exists {
		// Create a new index.

		mapping := `{
		    "settings":{
			 "number_of_shards":5,
			 "number_of_replicas":1
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
		}`
		createIndex, err := e.client.CreateIndex("ssh_activities").BodyString(mapping).Do(context.Background())
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
	log.Infof("ES activities %s", len(activities))
	buf := make([]byte, 32)
	docsc := make(chan attackerActivityDoc)
	g, ctx := errgroup.WithContext(context.TODO())
	begin := time.Now()
	e.createSSHActivitiesIndexIfnotExist()
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
		bulk := e.client.Bulk().Index("activities").Type("activity")
		for d := range docsc {
			// Simple progress
			current := atomic.AddUint64(&total, 1)
			dur := time.Since(begin).Seconds()
			sec := int(dur)
			pps := int64(float64(current) / dur)
			log.Debugf("%10d | %6d req/s | %02d:%02d\r", current, pps, sec/60, sec%60)

			// Enqueue the document
			log.Info(d)
			bulk.Add(elastic.NewBulkIndexRequest().Id(d.ID).Doc(d))
			if bulk.NumberOfActions() >= e.bulkSize {
				// Commit
				res, err := bulk.Do(ctx)
				if err != nil {
					return err
				}
				if res.Errors {
					// Look up the failed documents with res.Failed(), and e.g. recommit
					log.Info(res.Items)

					for _, s := range res.Items {
						for k, v := range s {
							log.Infof("%s %s", k, v)
						}
					}
					log.Info()
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
	fmt.Printf("%10d | %6d req/s | %02d:%02d\n", total, pps, sec/60, sec%60)

	return nil
}

func (e ElasticOutputClient) WriteAttackerLoginAttempts(attempts []parsers.AttackerLoginAttempt) error {
	for _, attempt := range attempts {
		log.Infof("%+v", attempt)
	}
	return nil
}

func (e *ElasticOutputClient) Init() error {
	log.Info("initialize ES")
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
