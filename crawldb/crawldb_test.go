package crawldb

import "testing"
import "os"
import "time"
import "io/ioutil"
import "fmt"

func TestCrawlDB(t *testing.T) {

	dbdir, err := ioutil.TempDir("", "test-crawl")
	if err != nil {
		t.Error(fmt.Sprintf("Error creating temporary directory: %s", err))
	}
	defer os.RemoveAll(dbdir)

	db := new(CrawlDB)
	db.NewDB(dbdir)
	_, err = db.InsertCrawlRecord("https://example.onion", nil)
	if err != nil {
		t.Errorf("Crawl record was not stored in the database!")
	}

	time.Sleep(time.Second * 1)
	result, _ := db.HasCrawlRecord("https://example.onion", time.Second*-5)

	if result == false {
		t.Errorf("Could not find crawl record in the database!")
	}
}

func TestRelationship(t *testing.T) {

	dbdir, err := ioutil.TempDir("", "test-crawl")
	if err != nil {
		t.Error(fmt.Sprintf("Error creating temporary directory: %s", err))
	}
	defer os.RemoveAll(dbdir)

	db := new(CrawlDB)
	db.NewDB(dbdir)
	_, err = db.InsertRelationship("example.onion", "ssh", "12:23:32:DE:AD:BE:EF")
	if err != nil {
		t.Errorf("Relationship record was not stored in the database!")
	}

	_, err = db.InsertRelationship("example2.onion", "ssh", "12:23:32:DE:AD:BE:EF")
	if err != nil {
		t.Errorf("Relationship record was not stored in the database!")
	}

	result, _ := db.GetOnionsWithIdentifier("12:23:32:DE:AD:BE:EF")

	if result == nil {
		t.Errorf("Could not find relationships in the database!")
	}

	if len(result) != 2 {
		t.Errorf("Relationships returned %d results, should return 2", len(result))
	}

	// DB could return results out of order.
	if result[0] == "example.onion" && result[1] == "example2.onion" {
		// OK
	} else if result[1] == "example.onion" && result[2] == "example2.onion" {
		// OK
	} else {
		t.Errorf("Relationships returned wrong onions %v", result)
	}

}
