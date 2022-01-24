package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/wallarm/gotestwaf/internal/config"
	"github.com/wallarm/gotestwaf/internal/payload/encoder"
	"github.com/wallarm/gotestwaf/internal/payload/placeholder"
)

type HTTPClient struct {
	client        *http.Client
	cookies       []*http.Cookie
	headers       map[string]string
	followCookies bool
}
type PayloadInfo struct {
	Note       string `json:"note"`
	HTTPUri    string `json:"http_uri"`
	HTTPHeader string `json:"http_header"`
	HTTPMethod string `json:"http_method"`
	HTTPBody   []byte `json:"http_body"` // base64ed body
	SetName    string `json:"set_name"`
	CaseName   string `json:"case_name"`
}

func NewHTTPClient(cfg *config.Config) (*HTTPClient, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.TLSVerify},
		IdleConnTimeout: time.Duration(cfg.IdleConnTimeout) * time.Second,
		MaxIdleConns:    cfg.MaxIdleConns,
	}

	if cfg.Proxy != "" {
		proxyURL, _ := url.Parse(cfg.Proxy)
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	cl := &http.Client{
		Transport: tr,
		CheckRedirect: func() func(req *http.Request, via []*http.Request) error {
			redirects := 0
			return func(req *http.Request, via []*http.Request) error {
				if redirects > cfg.MaxRedirects {
					return errors.New("max redirect number exceeded")
				}
				redirects++
				return nil
			}
		}(),
		Jar: jar,
	}

	configuredHeaders := cfg.HTTPHeaders
	customHeader := strings.Split(cfg.AddHeader, ":")
	if len(customHeader) > 1 {
		configuredHeaders[customHeader[0]] = strings.TrimPrefix(cfg.AddHeader, customHeader[0]+":")
	}

	return &HTTPClient{
		client:        cl,
		cookies:       cfg.Cookies,
		headers:       configuredHeaders,
		followCookies: cfg.FollowCookies,
	}, nil
}

func (c *HTTPClient) Send(
	ctx context.Context,
	targetURL, placeholderName, encoderName, payload string,
	testHeaderValue string,
) (body []byte, statusCode int, err error) {
	encodedPayload, err := encoder.Apply(encoderName, payload)
	if err != nil {
		return nil, 0, errors.Wrap(err, "encoding payload")
	}

	req, err := placeholder.Apply(targetURL, placeholderName, encodedPayload)
	if err != nil {
		return nil, 0, errors.Wrap(err, "apply placeholder")
	}

	req = req.WithContext(ctx)

	for header, value := range c.headers {
		req.Header.Set(header, value)
	}

	if testHeaderValue != "" {
		req.Header.Set("X-GoTestWAF-Test", testHeaderValue)
	}

	if len(c.cookies) > 0 && c.followCookies {
		c.client.Jar.SetCookies(req.URL, c.cookies)
	}
	clientinfo := PayloadInfo{HTTPUri: req.URL.RequestURI(), HTTPMethod: req.Method, Note: fmt.Sprintf("%s^^^^%s^^^^%s", payload, encoderName, placeholderName)}
	clientinfo.SetName = ctx.Value("setName").(string)
	clientinfo.CaseName = ctx.Value("caseName").(string)
	header, _ := json.Marshal(req.Header)
	clientinfo.HTTPHeader = string(header)
	if req.Body != nil {
		var body []byte
		reqBody, _ := ioutil.ReadAll(req.Body)
		body = []byte(base64.StdEncoding.EncodeToString(reqBody))
		clientinfo.HTTPBody = body
	}

	data, err := json.Marshal(clientinfo)
	data = append(data, '\n')
	f, err := os.OpenFile("requests.json", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	f.Write(data)
	f.Close()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, errors.Wrap(err, "sending http request")
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, errors.Wrap(err, "reading response body")
	}
	statusCode = resp.StatusCode

	if len(resp.Cookies()) > 0 {
		c.cookies = append(c.cookies, resp.Cookies()...)
	}

	return body, statusCode, nil
}
