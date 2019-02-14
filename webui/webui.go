package webui

import (
	"errors"
	"fmt"
	"github.com/s-rah/onionscan/config"
	"github.com/s-rah/onionscan/crawldb"
	"github.com/s-rah/onionscan/utils"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type WebUI struct {
	osc   *config.OnionScanConfig
	token string
	Done  chan bool
}

type SummaryField struct {
	Key      string
	Value    int
	AltTitle string
	Total    int
}

type Summary struct {
	Fields []SummaryField
	Total  int
	Title  string
}

type Content struct {
	SearchTerm      string
	Error           string
	Summary         Summary
	Tables          []Table
	Tags            []string
	RelationshipNum int
	Token           string
	Success         string
	UserTags        []string
	SearchResults   []string
}

type Row struct {
	Fields []string
	Tag    string
	Links  int
}

type Table struct {
	Title        string
	SearchTerm   string
	Heading      []string
	Rows         []Row
	Rollups      []int
	RollupCounts map[string]int
	AltTitle     string
}

// GetUserDefinedTable returns, from an initial relationship, a complete user
// defined relationship row - in the order it is defined in the crawl config.
func (wui *WebUI) GetUserDefinedTable(rel crawldb.Relationship) (Table, error) {
	log.Printf("Loading User Defined Relationship %s", rel.From)
	config, ok := wui.osc.CrawlConfigs[rel.From]
	if ok {
		var table Table
		crName := strings.SplitN(rel.Type, "/", 2)
		if len(crName) == 2 {
			table.Title = crName[0]
			cr, err := config.GetRelationship(crName[0])
			if err == nil {
				for i, er := range cr.ExtraRelationships {
					table.Heading = append(table.Heading, er.Name)
					if er.Rollup {
						table.Rollups = append(table.Rollups, i)
					}
				}
				table.Heading = append(table.Heading, "Onion")
				log.Printf("Returning User Table Relationship %v", table)
				return table, nil
			}
		}
	}
	log.Printf("Could not make Table")
	return Table{}, errors.New("Invalid Table")
}

// GetUserDefinedRow returns, from an initial relationship, a complete user
// defined relationship row - in the order it is defined in the crawl config.
func (wui *WebUI) GetUserDefinedRow(rel crawldb.Relationship) (string, []string) {
	log.Printf("Loading User Defined Relationship %s", rel.From)
	config, ok := wui.osc.CrawlConfigs[rel.From]

	if ok {
		userrel, err := wui.osc.Database.GetUserRelationshipFromOnion(rel.Onion, rel.From)

		if err == nil {
			// We can now construct the user
			// relationship in the right order.
			crName := strings.SplitN(rel.Type, "/", 2)
			if len(crName) == 2 {
				cr, err := config.GetRelationship(crName[0])
				row := make([]string, 0)
				if err == nil {
					for _, er := range cr.ExtraRelationships {
						log.Printf("Field Value: %v", userrel[crName[0]+"/"+er.Name].Identifier)
						row = append(row, userrel[crName[0]+"/"+er.Name].Identifier)
					}
					row = append(row, rel.From)
					log.Printf("Returning User Row Relationship %s %v %s", crName[0], row, rel.Onion)
					return crName[0], row
				}

			} else {
				log.Printf("Could not derive config relationship from type %s", rel.Type)
			}
		}
	}
	log.Printf("Invalid Row")
	return "", []string{}
}

// Save implements the Saved Searches Feature
func (wui *WebUI) Save(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Redirect(w, r, "/?error=Something Went Very Wrong! Please try again.", http.StatusFound)
		return
	}

	search := r.PostFormValue("search")
	token := r.PostFormValue("token")

	if token != wui.token {
		path := fmt.Sprintf("/?search=%v&error=Invalid random token, Please try again.", search)
		http.Redirect(w, r, path, http.StatusFound)
		return
	}

	wui.osc.Database.InsertRelationship(search, "onionscan://user-data", "search", "")
	path := fmt.Sprintf("/?search=%v&success=Successfully Saved Search", search)
	http.Redirect(w, r, path, http.StatusFound)
}

// Tag implements the /tag endpoint.
func (wui *WebUI) Tag(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Redirect(w, r, "/?error=Something Went Very Wrong! Please try again.", http.StatusFound)
		return
	}

	search := r.PostFormValue("search")
	tag := r.PostFormValue("tag")
	token := r.PostFormValue("token")

	if token != wui.token {
		path := fmt.Sprintf("/?search=%v&error=Invalid random token, Please try again.", search)
		http.Redirect(w, r, path, http.StatusFound)
		return
	}

	wui.osc.Database.InsertRelationship(search, "onionscan://user-data", "tag", tag)
	path := fmt.Sprintf("/?search=%v&success=Successfully Added Tag %v to %v", search, tag, search)
	http.Redirect(w, r, path, http.StatusFound)
}

// DeleteTag: Delete tag implements the /delete-tag endpoint
func (wui *WebUI) DeleteTag(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Redirect(w, r, "/?error=Something Went Very Wrong! Please try again.", http.StatusFound)
		return
	}

	search := r.PostFormValue("search")
	tag := r.PostFormValue("tag")
	token := r.PostFormValue("token")

	if token != wui.token {
		path := fmt.Sprintf("/?search=%v&error=Invalid random token, Could not delete tag. Please try again.", search)
		http.Redirect(w, r, path, http.StatusFound)
		return
	}

	err = wui.osc.Database.DeleteRelationship(search, "onionscan://user-data", "tag", tag)

	if err != nil {
		http.Redirect(w, r, "/?error=Something Went Very Wrong! Please try again: "+err.Error(), http.StatusFound)
		return
	}

	path := fmt.Sprintf("/?search=%v&success=Successfully Deleted Tag %v from %v", search, tag, search)
	http.Redirect(w, r, path, http.StatusFound)
}

// SavedSearches provides the user with a list of searches they have saved.
func (wui *WebUI) SavedSearches(w http.ResponseWriter, r *http.Request) {
	results, _ := wui.osc.Database.GetRelationshipsWithIdentifier("onionscan://user-data")
	var content Content
	content.SearchResults = append(content.SearchResults, "onionscan://dummy")
	for _, rel := range results {
		if rel.Type == "search" {
			content.SearchResults = append(content.SearchResults, rel.Onion)
		}
	}
	var templates = template.Must(template.ParseFiles("templates/index.html"))
	templates.ExecuteTemplate(w, "index.html", content)
}

// Index implements the main search functionality of the webui
func (wui *WebUI) Index(w http.ResponseWriter, r *http.Request) {

	search := strings.TrimSpace(r.URL.Query().Get("search"))
	error := strings.TrimSpace(r.URL.Query().Get("error"))
	success := strings.TrimSpace(r.URL.Query().Get("success"))
	var content Content

	mod_status := false
	pgp := false
	ssh := false
	uriCount := 0
	content.Token = wui.token
	content.Error = error
	content.Success = success

	if search != "" {
		content.SearchTerm = search

		var results []crawldb.Relationship
		tables := make(map[string]Table)

		results, _ = wui.osc.Database.GetRelationshipsWithOnion(search)
		results_identifier, _ := wui.osc.Database.GetRelationshipsWithIdentifier(search)
		results = append(results, results_identifier...)

		for _, rel := range results {
			if rel.Type == "page-info" {
				content.Summary.Title = rel.Identifier
			}

			if rel.From == "onionscan://user-data" {
				if rel.Type == "tag" {
					content.UserTags = append(content.UserTags, rel.Identifier)
					utils.RemoveDuplicates(&content.UserTags)

					if rel.Identifier == search {
						// We want to surface the onions *not* the tag

						table, ok := tables["search-results"]
						log.Printf("%v %v", search, ok)
						if !ok {
							var newTable Table
							newTable.Title = rel.Type
							newTable.Heading = []string{"Onion"}
							tables["search-results"] = newTable
							table = newTable
						}
						links := wui.osc.Database.GetRelationshipsCount(rel.Identifier) - 1
						table.Rows = append(table.Rows, Row{Fields: []string{rel.Onion}, Tag: rel.Identifier, Links: links})
						tables["search-results"] = table
					} else {
						table, ok := tables["search-results"]
						if !ok {
							var newTable Table
							newTable.Title = rel.Type
							newTable.Heading = []string{"Tags"}
							tables[rel.Type] = newTable
							table = newTable
						}
						links := wui.osc.Database.GetRelationshipsCount(rel.Identifier) - 1
						table.Rows = append(table.Rows, Row{Fields: []string{rel.Identifier}, Tag: rel.Onion, Links: links})
						tables[rel.Type] = table
					}
				}
			} else if utils.IsOnion(rel.Onion) && rel.Type != "database-id" && rel.Type != "user-relationship" {
				table, ok := tables[rel.Type]
				if !ok {
					var newTable Table
					newTable.Title = rel.Type
					newTable.Heading = []string{"Identifier", "Onion"}
					tables[rel.Type] = newTable
					table = newTable
				}
				links := wui.osc.Database.GetRelationshipsCount(rel.Identifier) - 1
				table.Rows = append(table.Rows, Row{Fields: []string{rel.Identifier, rel.Onion}, Tag: rel.From, Links: links})
				tables[rel.Type] = table

				if rel.From == "mod_status" {
					mod_status = true
				}

				if rel.From == "pgp" {
					pgp = true
				}

				if rel.From == "ssh" {
					ssh = true
				}
			} else if utils.IsOnion(rel.From) {
				tableName, row := wui.GetUserDefinedRow(rel)

				if len(row) > 0 {
					table, exists := tables[tableName]
					if !exists {
						newTable, err := wui.GetUserDefinedTable(rel)
						if err == nil {
							tables[tableName] = newTable
							table = newTable
						}
					}
					table.Rows = append(table.Rows, Row{Fields: row})
					tables[tableName] = table
				}
			} else if rel.Type == "user-relationship" {
				userrel := rel
				userrel.Onion = rel.Identifier
				userrel.From = rel.Onion
				userrel.Type = rel.From + "/parent"
				tableName, row := wui.GetUserDefinedRow(userrel)

				if len(row) > 0 {
					table, exists := tables[tableName]
					if !exists {
						newTable, err := wui.GetUserDefinedTable(userrel)
						if err == nil {
							tables[tableName] = newTable
							table = newTable
						}
					}
					table.Rows = append(table.Rows, Row{Fields: row})
					tables[tableName] = table
				}
			} else if rel.Type == "database-id" {
				uriCount++
			}
		}

		// AutoTag our content
		if mod_status {
			content.Tags = append(content.Tags, "mod_status")
		}

		if pgp {
			content.Tags = append(content.Tags, "pgp")
		}

		if ssh {
			content.Tags = append(content.Tags, "ssh")
		}

		// We now have a bunch of tables, keyed by type.
		// Build a Summary and add the tables to the Content

		for _, v := range tables {
			content.Summary.Total += len(v.Rows)
		}

		for k, v := range tables {
			log.Printf("Adding Table %s %v", k, v)

			// Lazy Plural
			alt := k + "s"

			switch k {
			case "ip":
				alt = "IP Addresses"
			case "clearnet-link":
				alt = "Co-Hosted Clearnet Sites"
			case "uri":
				alt = "Links to External Sites"
			case "email-address":
				alt = "Email Addresses"
			case "server-version":
				alt = "Server Information"
			case "identity":
				alt = "PGP Identities"
			case "bitcoin-address":
				alt = "Bitcoin Addresses"
			case "software-banner":
				alt = "Software Banners"
			case "analytics-id":
				alt = "Analytics IDs"
			case "tag":
				alt = "Tag Relationships"
			case "onion":
				alt = "Co-Hosted Onion Sites"
			case "search-results":
				alt = "Search Results"
			case "http-header":
				alt = "HTTP Headers"
			case "page-info":
				alt = "Webpage Information"
			}

			total := (float32(len(v.Rows)) / float32(content.Summary.Total)) * float32(100)
			if total < 1 {
				total = 2 // For Visibility
			}

			field := SummaryField{k, len(v.Rows), alt, int(total)}
			content.Summary.Fields = append(content.Summary.Fields, field)

			rollups := make(map[string]int)
			for _, c := range v.Rollups {
				for _, rows := range v.Rows {
					rollups[rows.Fields[c]]++
				}
			}
			v.RollupCounts = rollups
			v.SearchTerm = search
			v.AltTitle = alt
			content.Tables = append(content.Tables, v)
		}

	} else {
		content.RelationshipNum = wui.osc.Database.GetAllRelationshipsCount()
	}

	var templates = template.Must(template.ParseFiles("templates/index.html"))
	templates.ExecuteTemplate(w, "index.html", content)
}

func (wui *WebUI) Listen(osc *config.OnionScanConfig, port int) {
	wui.osc = osc

	// We generate a random token on startup to mitigate the threat
	// against CSRF style attacks.
	token, err := utils.GenerateRandomString(64)
	if err != nil {
		log.Fatalf("Error generating random bytes for CSRF token: %v", err)
	}
	wui.token = token

	http.HandleFunc("/", wui.Index)
	http.HandleFunc("/save", wui.Save)
	http.HandleFunc("/tag", wui.Tag)
	http.HandleFunc("/saved", wui.SavedSearches)
	http.HandleFunc("/delete-tag", wui.DeleteTag)

	fs := http.FileServer(http.Dir("./templates/style"))
	http.Handle("/style/", http.StripPrefix("/style/", fs))

	fs = http.FileServer(http.Dir("./templates/scripts"))
	http.Handle("/scripts/", http.StripPrefix("/scripts/", fs))

	fs = http.FileServer(http.Dir("./templates/images"))
	http.Handle("/images/", http.StripPrefix("/images/", fs))

	fs = http.FileServer(http.Dir("./templates/fonts"))
	http.Handle("/fonts/", http.StripPrefix("/fonts/", fs))

	portstr := strconv.Itoa(port)
	http.ListenAndServe("127.0.0.1:"+portstr, nil)
}
