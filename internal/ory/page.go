package ory

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// Page is one page of a listing and the token of the next ("" at the end).
type Page[T any] struct {
	Items []T
	Next  string
}

func paging(q url.Values, size int, token string) {
	if size > 0 {
		q.Set("page_size", strconv.Itoa(size))
	}

	if token != "" {
		q.Set("page_token", token)
	}
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextToken is the page_token of the Link rel="next" header; "" without one.
func nextToken(h http.Header) string {
	for _, link := range h.Values("Link") {
		m := linkNext.FindStringSubmatch(link)
		if m == nil {
			continue
		}

		u, err := url.Parse(m[1])
		if err != nil {
			continue
		}

		return u.Query().Get("page_token")
	}

	return ""
}
