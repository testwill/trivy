package grypedb

import (
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/store"
)

func LoadVulnerabilityDB(cfg db.Config) (*store.Store, *db.Status, *db.Closer, error) {
	dbCurator, err := db.NewCurator(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	storeReader, dbCloser, err := dbCurator.GetStore()
	if err != nil {
		return nil, nil, nil, err
	}

	status := dbCurator.Status()

	p, err := db.NewVulnerabilityProvider(storeReader)
	if err != nil {
		return nil, &status, nil, err
	}

	s := &store.Store{
		Provider: p,
	}

	closer := &db.Closer{DBCloser: dbCloser}

	return s, &status, closer, nil
}
