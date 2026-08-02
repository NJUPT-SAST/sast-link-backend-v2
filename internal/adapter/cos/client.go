// Package cos implements the objectstore ports against Tencent Cloud COS
// (PRD §1.1 object storage choice). Uploads are stored under the configured
// bucket with public-read ACL; the review uses the synchronous CI image
// auditing endpoint (sensitive-content-recognition).
package cos

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tencentyun/cos-go-sdk-v5"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
)

// Config carries the COS connection settings. Validate was already applied by
// internal/config; this struct only fails when the values cannot form a client.
type Config struct {
	// Endpoint overrides the bucket access host (bucket name included), e.g. an
	// internal or CDN domain. Empty means {bucket}.cos.{region}.myqcloud.com.
	Endpoint string
	Region   string
	Bucket   string
	// AccessKey / SecretKey are the COS API credentials (SecretId/SecretKey).
	AccessKey string
	SecretKey string
	// BaseURL prefixes public object URLs when set (e.g. a CDN domain). Empty
	// falls back to the bucket access host.
	BaseURL string
}

// Client is a COS-backed objectstore.ObjectStore with image review.
type Client struct {
	client  *cos.Client
	bucket  string
	baseURL string
}

// New builds a COS client. The bucket must be in {name}-{appid} form; the SDK
// rejects anything else, which doubles as a configuration sanity check.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.Bucket) == "" ||
		strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, fmt.Errorf("cos: region, bucket, access key and secret key are all required")
	}
	var bucketURL *url.URL
	if strings.TrimSpace(cfg.Endpoint) != "" {
		parsed, err := url.Parse("https://" + strings.TrimSpace(cfg.Endpoint))
		if err != nil {
			return nil, fmt.Errorf("cos: parse endpoint: %w", err)
		}
		bucketURL = parsed
	} else {
		generated, err := cos.NewBucketURL(strings.TrimSpace(cfg.Bucket), strings.TrimSpace(cfg.Region), true)
		if err != nil {
			return nil, fmt.Errorf("cos: build bucket URL: %w", err)
		}
		bucketURL = generated
	}
	sdkClient := cos.NewClient(&cos.BaseURL{BucketURL: bucketURL}, &http.Client{
		Transport: &cos.AuthorizationTransport{
			SecretID:  strings.TrimSpace(cfg.AccessKey),
			SecretKey: strings.TrimSpace(cfg.SecretKey),
		},
	})
	return &Client{
		client:  sdkClient,
		bucket:  strings.TrimSpace(cfg.Bucket),
		baseURL: strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
	}, nil
}

// Upload writes content under key with public-read ACL and returns its public
// URL (base URL when configured, the bucket access host otherwise).
func (c *Client) Upload(ctx context.Context, key string, r io.Reader, contentType string, size int64) (string, error) {
	if _, err := c.client.Object.Put(ctx, key, r, &cos.ObjectPutOptions{
		ACLHeaderOptions: &cos.ACLHeaderOptions{XCosACL: "public-read"},
		ObjectPutHeaderOptions: &cos.ObjectPutHeaderOptions{
			ContentType:   contentType,
			ContentLength: size,
		},
	}); err != nil {
		return "", fmt.Errorf("cos: upload %s: %w", key, err)
	}
	return c.PublicURL(key), nil
}

// Delete removes an object. A missing key is not an error (the SDK answers 204
// for delete on absent keys), matching the port contract.
func (c *Client) Delete(ctx context.Context, key string) error {
	if _, err := c.client.Object.Delete(ctx, key); err != nil {
		return fmt.Errorf("cos: delete %s: %w", key, err)
	}
	return nil
}

// AuditImage runs the synchronous CI image review for key and maps the verdict
// to an objectstore.AuditResult. A non-nil error means the review did not run —
// the caller must treat that as a rejected upload (fail-closed).
func (c *Client) AuditImage(ctx context.Context, key string) (objectstore.AuditResult, error) {
	result, _, err := c.client.CI.ImageAuditing(ctx, key, &cos.ImageRecognitionOptions{
		CIProcess:  "sensitive-content-recognition",
		DetectType: "porn,terrorist,politics,ads",
	})
	if err != nil {
		return objectstore.AuditResult{}, fmt.Errorf("cos: audit %s: %w", key, err)
	}
	sensitive := result.Result == 1
	for _, info := range []*cos.RecognitionInfo{
		result.PornInfo, result.TerroristInfo, result.PoliticsInfo, result.AdsInfo,
	} {
		if info != nil && info.HitFlag == 1 {
			sensitive = true
		}
	}
	label := strings.TrimSpace(result.Label)
	if label == "" {
		label = "unknown"
	}
	return objectstore.AuditResult{Sensitive: sensitive, Label: label}, nil
}

// PublicURL joins the configured base URL (or the bucket host) with key.
func (c *Client) PublicURL(key string) string {
	if c.baseURL != "" {
		return c.baseURL + "/" + key
	}
	return c.client.Object.GetObjectURL(key).String()
}

// Bucket returns the configured bucket name, for diagnostics.
func (c *Client) Bucket() string {
	return c.bucket
}
