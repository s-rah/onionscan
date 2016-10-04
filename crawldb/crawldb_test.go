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
