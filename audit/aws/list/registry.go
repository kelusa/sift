package list

import (
	"context"

	"sift/audit"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type Column = audit.ResourceColumn

type Lister struct {
	Service  string
	SubTypes []string            // optional sub-resources (e.g. ["jobs", "crawlers"])
	Columns  map[string][]Column // key = resource type (e.g. "job", "cluster"), value = columns
	Fn       func(ctx context.Context, cfg aws.Config, subType string) ([]audit.Resource, error)
}

var listers []Lister

func Register(l Lister) {
	listers = append(listers, l)
	for typ, cols := range l.Columns {
		audit.RegisterColumns(l.Service+"/"+typ, cols)
	}
}

func Get(service string) *Lister {
	for i := range listers {
		if listers[i].Service == service {
			return &listers[i]
		}
	}
	return nil
}

func Services() []string {
	var s []string
	for _, l := range listers {
		s = append(s, l.Service)
	}
	return s
}

func All() []Lister {
	return listers
}
