// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"encoding/json"
	"time"

	"github.com/DataDog/scfw/scfw/internal/ecosystem"
)

// Package is used as a Set element, so fields must compare by value; PublishDate is
// time.Time for this reason, even though *time.Time would be the more natural choice.
// A zero-valued PublishDate means the package's publication date is unknown.
type Package struct {
	Ecosystem   ecosystem.Ecosystem `json:"ecosystem"`
	Name        string              `json:"package_name"`
	Version     string              `json:"package_version"`
	Source      string              `json:"package_source,omitempty"`
	PublishDate time.Time           `json:"publish_date"`
}

// MarshalJSON omits PublishDate entirely when it is the zero value, since
// encoding/json's "omitempty" does not detect zero-valued structs.
func (p Package) MarshalJSON() ([]byte, error) {
	type aliasPackage struct {
		Ecosystem   ecosystem.Ecosystem `json:"ecosystem"`
		Name        string              `json:"package_name"`
		Version     string              `json:"package_version"`
		Source      string              `json:"package_source,omitempty"`
		PublishDate *time.Time          `json:"publish_date,omitempty"`
	}

	a := aliasPackage{
		Ecosystem: p.Ecosystem,
		Name:      p.Name,
		Version:   p.Version,
		Source:    p.Source,
	}
	if !p.PublishDate.IsZero() {
		a.PublishDate = &p.PublishDate
	}

	return json.Marshal(a)
}
