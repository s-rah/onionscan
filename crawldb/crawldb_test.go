package crawldb

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestCrawlDB(t *testing.T) {

	dbdir, err := ioutil.TempDir("", "test-crawl")
	if err != nil {
		t.Errorf("Error creating temporary directory: %s", err)
	}
	defer os.RemoveAll(dbdir)

	db := new(CrawlDB)
	db.NewDB(dbdir)
	_, err = db.InsertCrawlRecord("https://example.onion", nil)
	if err != nil {
		t.Errorf("Crawl record was not stored in the database!")
	}

	// Consistency
	time.Sleep(time.Second * 1)
	result, _ := db.HasCrawlRecord("https://example.onion", time.Second*-5)

	if result == false {
		t.Errorf("Could not find crawl record in the database!")
	}
}

func TestRelationship(t *testing.T) {

	dbdir, err := ioutil.TempDir("", "test-crawl")
	if err != nil {
		t.Errorf("Error creating temporary directory: %s", err)
	}
	defer os.RemoveAll(dbdir)

	db := new(CrawlDB)
	db.NewDB(dbdir)
	_, err = db.InsertRelationship("example.onion", "ssh", "", "12:23:32:DE:AD:BE:EF")
	if err != nil {
		t.Errorf("Relationship record was not stored in the database!")
	}

	_, err = db.InsertRelationship("example2.onion", "ssh", "", "12:23:32:DE:AD:BE:EF")
	if err != nil {
		t.Errorf("Relationship record was not stored in the database!")
	}

	// Consistency
	time.Sleep(time.Second * 1)
	result, _ := db.GetRelationshipsWithIdentifier("12:23:32:DE:AD:BE:EF")

	if result == nil {
		t.Errorf("Could not find relationships in the database!")
	}

	if len(result) != 2 {
		t.Errorf("Relationships returned %d results, should return 2", len(result))
	}

	// DB could return results in any order.
	if result[0].Onion == "example.onion" && result[1].Onion == "example2.onion" {
		// OK
	} else if result[1].Onion == "example.onion" && result[0].Onion == "example2.onion" {
		// OK
	} else {
		t.Errorf("Relationships returned wrong onions %v", result)
	}

}
