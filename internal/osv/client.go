package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const defaultBaseURL = "https://api.osv.dev/v1/query"

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		baseURL:    defaultBaseURL,
		httpClient: httpClient,
	}
}

func (c *Client) Query(ctx context.Context, request QueryRequest) (QueryResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return QueryResponse{}, fmt.Errorf("marshal osv request: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return QueryResponse{}, fmt.Errorf("create osv request: %w", err)
	}

	httpRequest.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return QueryResponse{}, fmt.Errorf("execute osv request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return QueryResponse{}, fmt.Errorf("osv query returned status %d", response.StatusCode)
	}

	var queryResponse QueryResponse
	if err := json.NewDecoder(response.Body).Decode(&queryResponse); err != nil {
		return QueryResponse{}, fmt.Errorf("decode osv response: %w", err)
	}

	return queryResponse, nil
}
