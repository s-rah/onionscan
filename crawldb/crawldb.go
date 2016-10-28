package crawldb

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/HouzuoGuo/tiedot/db"
	"github.com/s-rah/onionscan/model"
	"log"
	"time"
)

// CrawlDB is the main interface for persistent storage in OnionScan
type CrawlDB struct {
	myDB *db.DB
}

// NewDB creates new new CrawlDB instance. If the database does not exist at the
// given dbdir, it will be created.
func (cdb *CrawlDB) NewDB(dbdir string) {
	db, err := db.OpenDB(dbdir)
	if err != nil {
		panic(err)
	}
	cdb.myDB = db

	//If we have just created this db then it will be empty
	if len(cdb.myDB.AllCols()) == 0 {
		cdb.Initialize()
	}

}

// Initialize sets up a new database - should only be called when creating a
// new database.
// There is a lot of indexing here, which may seem overkill - but on a large
// OnionScan run these indexes take up < 100MB each - which is really cheap
// when compared with their search potential.
func (cdb *CrawlDB) Initialize() {
	log.Printf("Creating Database Bucket crawls...")
	if err := cdb.myDB.Create("crawls"); err != nil {
		panic(err)
	}

	// Allow searching by the URL
	log.Printf("Indexing URL in crawls...")
	crawls := cdb.myDB.Use("crawls")
	if err := crawls.Index([]string{"URL"}); err != nil {
		panic(err)
	}

	log.Printf("Creating Database Bucket relationships...")
	if err := cdb.myDB.Create("relationships"); err != nil {
		panic(err)
	}

	// Allowing searching by the Identifier String
	log.Printf("Indexing Identifier in relationships...")
	rels := cdb.myDB.Use("relationships")
	if err := rels.Index([]string{"Identifier"}); err != nil {
		panic(err)
	}

	// Allowing searching by the Onion String
	log.Printf("Indexing Onion in relationships...")
	if err := rels.Index([]string{"Onion"}); err != nil {
		panic(err)
	}

	// Allowing searching by the Type String
	log.Printf("Indexing Type in relationships...")
	if err := rels.Index([]string{"Type"}); err != nil {
		panic(err)
	}

	// Allowing searching by the From String
	log.Printf("Indexing From in relationships...")
	if err := rels.Index([]string{"From"}); err != nil {
		panic(err)
	}

	log.Printf("Database Setup Complete")

}

// CrawlRecord defines a spider entry in the database
type CrawlRecord struct {
	URL       string
	Timestamp time.Time
	Page      model.Page
}

// InsertCrawlRecord adds a new spider entry to the database and returns the
// record id.
func (cdb *CrawlDB) InsertCrawlRecord(url string, page *model.Page) (int, error) {
	crawls := cdb.myDB.Use("crawls")
	docID, err := crawls.Insert(map[string]interface{}{
		"URL":       url,
		"Timestamp": time.Now(),
		"Page":      page})
	return docID, err
}

// GetCrawlRecord returns a CrawlRecord from the database given an ID.
func (cdb *CrawlDB) GetCrawlRecord(id int) (CrawlRecord, error) {
	crawls := cdb.myDB.Use("crawls")
	readBack, err := crawls.Read(id)
	if err == nil {
		out, err := json.Marshal(readBack)
		if err == nil {
			var crawlRecord CrawlRecord
			json.Unmarshal(out, &crawlRecord)
			return crawlRecord, nil
		}
		return CrawlRecord{}, err
	}
	return CrawlRecord{}, err
}

// HasCrawlRecord returns true if a given URL is associated with a crawl record
// in the database. Only records created after the given duration are considered.
func (cdb *CrawlDB) HasCrawlRecord(url string, duration time.Duration) (bool, int) {
	var query interface{}
	before := time.Now().Add(duration)

	q := fmt.Sprintf(`{"eq":"%v", "in": ["URL"]}`, url)
	json.Unmarshal([]byte(q), &query)

	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	crawls := cdb.myDB.Use("crawls")
	if err := db.EvalQuery(query, crawls, &queryResult); err != nil {
		panic(err)
	}

	for id := range queryResult {
		// To get query result document, simply read it
		readBack, err := crawls.Read(id)
		if err == nil {
			out, err := json.Marshal(readBack)
			if err == nil {
				var crawlRecord CrawlRecord
				json.Unmarshal(out, &crawlRecord)

				if crawlRecord.Timestamp.After(before) {
					return true, id
				}
			}
		}

	}

	return false, 0
}

// Relationship defines a correltion record in the Database.
type Relationship struct {
	ID         int
	Onion      string
	From       string
	Type       string
	Identifier string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// InsertRelationship creates a new Relationship in the database.
func (cdb *CrawlDB) InsertRelationship(onion string, from string, identiferType string, identifier string) (int, error) {

	rels, err := cdb.GetRelationshipsWithOnion(onion)

	// If we have seen this before, we will update rather than adding a
	// new relationship
	if err == nil {
		for _, rel := range rels {
			if rel.From == from && rel.Identifier == identifier && rel.Type == identiferType {
				// Update the Relationships
				log.Printf("Updating %s --- %s ---> %s (%s)", onion, from, identifier, identiferType)
				relationships := cdb.myDB.Use("relationships")
				err := relationships.Update(rel.ID, map[string]interface{}{
					"Onion":      onion,
					"From":       from,
					"Type":       identiferType,
					"Identifier": identifier,
					"FirstSeen":  rel.FirstSeen,
					"LastSeen":   time.Now()})
				return rel.ID, err
			}
		}
	}

	// Otherwise Insert New
	log.Printf("Inserting %s --- %s ---> %s (%s)", onion, from, identifier, identiferType)
	relationships := cdb.myDB.Use("relationships")
	docID, err := relationships.Insert(map[string]interface{}{
		"Onion":      onion,
		"From":       from,
		"Type":       identiferType,
		"Identifier": identifier,
		"FirstSeen":  time.Now(),
		"LastSeen":   time.Now()})
	return docID, err
}

// GetRelationshipsWithOnion returns all relationships with an Onion field matching
// the onion parameter.
func (cdb *CrawlDB) GetRelationshipsWithOnion(onion string) ([]Relationship, error) {
	return cdb.queryDB("Onion", onion)
}

// GetUserRelationshipFromOnion reconstructs a user relationship from a given
// identifier. fromonion is used as a filter to ensure that only user relationships
// from a given onion are reconstructed.
func (cdb *CrawlDB) GetUserRelationshipFromOnion(identifier string, fromonion string) (map[string]Relationship, error) {
	results, err := cdb.GetRelationshipsWithOnion(identifier)

	if err != nil {
		return nil, err
	}

	relationships := make(map[string]Relationship)
	for _, result := range results {
		if result.From == fromonion {
			relationships[result.Type] = result
		}
	}
	return relationships, nil
}

// GetAllRelationshipsCount returns the total number of relationships stored in
// the database.
func (cdb *CrawlDB) GetAllRelationshipsCount() int {
	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	relationships := cdb.myDB.Use("relationships")

	if err := db.EvalAllIDs(relationships, &queryResult); err != nil {
		return 0
	}
	return len(queryResult)
}

// GetRelationshipsCount returns the total number of relationships for a given
// identifier.
func (cdb *CrawlDB) GetRelationshipsCount(identifier string) int {
	var query interface{}

	q := fmt.Sprintf(`{"eq":"%v", "in": ["Identifier"]}`, identifier)
	json.Unmarshal([]byte(q), &query)

	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	relationships := cdb.myDB.Use("relationships")
	if err := db.EvalQuery(query, relationships, &queryResult); err != nil {
		return 0
	}
	return len(queryResult)
}

// GetRelationshipsWithIdentifier returns all relatioships associated with a
// given identifier.
func (cdb *CrawlDB) GetRelationshipsWithIdentifier(identifier string) ([]Relationship, error) {

	types, _ := cdb.queryDB("Type", identifier)
	froms, _ := cdb.queryDB("From", identifier)
	identifiers, _ := cdb.queryDB("Identifier", identifier)

	queryResult := append(types, froms...)
	queryResult = append(queryResult, identifiers...)

	return queryResult, nil
}

func (cdb *CrawlDB) queryDB(field string, value string) ([]Relationship, error) {
	var query interface{}

	q := fmt.Sprintf(`{"eq":"%v", "in": ["%v"]}`, value, field)
	json.Unmarshal([]byte(q), &query)

	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	relationships := cdb.myDB.Use("relationships")
	if err := db.EvalQuery(query, relationships, &queryResult); err != nil {
		return nil, err
	}
	var rels []Relationship

	for id := range queryResult {
		// To get query result document, simply read it
		readBack, err := relationships.Read(id)
		if err == nil {
			out, err := json.Marshal(readBack)
			if err == nil {
				var relationship Relationship
				json.Unmarshal(out, &relationship)
				relationship.ID = id
				rels = append(rels, relationship)
			}
		}
	}
	return rels, nil
}

// DeleteRelationship deletes a relationship given the quad.
func (cdb *CrawlDB) DeleteRelationship(onion string, from string, identiferType string, identifier string) error {
	relationships := cdb.myDB.Use("relationships")
	rels, err := cdb.GetRelationshipsWithOnion(onion)
	if err == nil {
		for _, rel := range rels {
			if rel.From == from && rel.Type == identiferType && rel.Identifier == identifier {
				err := relationships.Delete(rel.ID)
				return err
			}
		}
	}
	return errors.New("could not find record to delete")
}
