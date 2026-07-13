package httpclient

import (
	"time"

	fanghttp "github.com/aydocs/fang/internal/http"
)

type Client struct {
	client *fanghttp.Client
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		client: fanghttp.NewClient(
			fanghttp.WithTimeout(timeout),
		),
	}
}

func (c *Client) Do(req *fanghttp.Request) (*fanghttp.Response, error) {
	return c.client.Do(req)
}

func (c *Client) Get(url string) (*fanghttp.Response, error) {
	return c.client.Get(url)
}

func (c *Client) Post(url, body string) (*fanghttp.Response, error) {
	return c.client.Post(url, body)
}

func (c *Client) Put(url, body string) (*fanghttp.Response, error) {
	return c.client.Put(url, body)
}

func (c *Client) Head(url string) (*fanghttp.Response, error) {
	return c.client.Head(url)
}

func (c *Client) Delete(url string) (*fanghttp.Response, error) {
	return c.client.Delete(url)
}

func (c *Client) Options(url string) (*fanghttp.Response, error) {
	return c.client.Options(url)
}

func (c *Client) DoRaw(method, targetURL string, headers map[string]string) (*fanghttp.Response, error) {
	return c.client.DoRaw(method, targetURL, headers, "")
}

func (c *Client) GetWithHeaders(url string, headers map[string]string) (*fanghttp.Response, error) {
	return c.client.DoRaw("GET", url, headers, "")
}

func (c *Client) Config() *fanghttp.Config {
	return c.client.Config()
}

func (c *Client) Close() {
	c.client.Close()
}
