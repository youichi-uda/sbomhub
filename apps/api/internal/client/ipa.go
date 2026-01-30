package client

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// IPAClient is a client for fetching IPA security information
type IPAClient struct {
	httpClient *http.Client
}

// NewIPAClient creates a new IPA client
func NewIPAClient() *IPAClient {
	return &IPAClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IPAFeedItem represents an item from IPA RSS feed
type IPAFeedItem struct {
	IPAID       string
	Title       string
	Description string
	Link        string
	Category    string
	Severity    string
	RelatedCVEs []string
	PublishedAt time.Time
}

// RSS feed structure
type rssResponse struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

// IPA RSS feed URLs
const (
	IPASecurityAlertURL     = "https://www.ipa.go.jp/security/alert/alert.rdf"
	IPAVulnerabilityNoteURL = "https://jvndb.jvn.jp/ja/rss/jvndb.rdf"
)

// FetchSecurityAlerts fetches IPA security alerts
func (c *IPAClient) FetchSecurityAlerts(ctx context.Context) ([]IPAFeedItem, error) {
	return c.fetchRSSFeed(ctx, IPASecurityAlertURL, "security_alert")
}

// FetchVulnerabilityNotes fetches JVN vulnerability notes
func (c *IPAClient) FetchVulnerabilityNotes(ctx context.Context) ([]IPAFeedItem, error) {
	return c.fetchRSSFeed(ctx, IPAVulnerabilityNoteURL, "vulnerability_note")
}

func (c *IPAClient) fetchRSSFeed(ctx context.Context, url, category string) ([]IPAFeedItem, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rss rssResponse
	if err := xml.Unmarshal(body, &rss); err != nil {
		return nil, fmt.Errorf("failed to parse RSS: %w", err)
	}

	var items []IPAFeedItem
	for _, item := range rss.Channel.Items {
		pubDate, _ := parseRSSDate(item.PubDate)

		feedItem := IPAFeedItem{
			IPAID:       item.GUID,
			Title:       item.Title,
			Description: item.Description,
			Link:        item.Link,
			Category:    category,
			PublishedAt: pubDate,
		}

		// Extract CVE IDs from title and description
		feedItem.RelatedCVEs = extractCVEIDs(item.Title + " " + item.Description)

		// Determine severity from title/description
		feedItem.Severity = determineSeverity(item.Title + " " + item.Description)

		items = append(items, feedItem)
	}

	return items, nil
}

// parseRSSDate parses various date formats found in RSS feeds
func parseRSSDate(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC1123,
		time.RFC1123Z,
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Now(), fmt.Errorf("failed to parse date: %s", dateStr)
}

// extractCVEIDs extracts CVE IDs from text
func extractCVEIDs(text string) []string {
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	matches := cvePattern.FindAllString(text, -1)

	// Deduplicate
	seen := make(map[string]bool)
	var result []string
	for _, cve := range matches {
		cve = strings.ToUpper(cve)
		if !seen[cve] {
			seen[cve] = true
			result = append(result, cve)
		}
	}

	return result
}

// determineSeverity determines severity from text content
func determineSeverity(text string) string {
	textLower := strings.ToLower(text)

	if strings.Contains(textLower, "緊急") ||
		strings.Contains(textLower, "critical") ||
		strings.Contains(textLower, "immediate") {
		return "CRITICAL"
	}

	if strings.Contains(textLower, "重要") ||
		strings.Contains(textLower, "high") ||
		strings.Contains(textLower, "important") {
		return "HIGH"
	}

	if strings.Contains(textLower, "警告") ||
		strings.Contains(textLower, "medium") ||
		strings.Contains(textLower, "moderate") {
		return "MEDIUM"
	}

	if strings.Contains(textLower, "注意") ||
		strings.Contains(textLower, "low") {
		return "LOW"
	}

	return "INFO"
}
