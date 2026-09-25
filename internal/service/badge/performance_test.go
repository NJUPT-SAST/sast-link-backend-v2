package badge

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

type measuredCards struct {
	avatar  *string
	calls   atomic.Int64
	delay   time.Duration
	entered chan struct{}
	release chan struct{}
}

func (r *measuredCards) FindPublicCardByUserID(ctx context.Context, _ int64) (*repository.PublicCard, error) {
	r.calls.Add(1)
	if r.entered != nil {
		select {
		case r.entered <- struct{}{}:
		default:
		}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	card := nicknameCard("张三")
	card.Avatar = r.avatar
	return card, nil
}
func performanceService(tb testing.TB, cards *measuredCards) (*Service, *fakeBadgeRepository) {
	tb.Helper()
	badges := newFakeBadgeRepository()
	if err := badges.Create(context.Background(), &model.Badge{UserID: 7, BadgeKey: "burst-key"}); err != nil {
		tb.Fatal(err)
	}
	service := newTestService(nil, badges, &fakeAuditRepository{})
	service.Users = cards
	return service, badges
}
func TestRenderCoalescesColdBurst(t *testing.T) {
	cards := &measuredCards{entered: make(chan struct{}, 32), release: make(chan struct{})}
	service, _ := performanceService(t, cards)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			result, err := service.Render(context.Background(), RenderInput{Key: "burst-key"})
			if err != nil || result.NotFound {
				t.Errorf("render: %v", err)
			}
		})
	}
	<-cards.entered
	// Keep the leader busy while the rest of the burst arrives.
	time.Sleep(30 * time.Millisecond)
	close(cards.release)
	wg.Wait()
	if n := cards.calls.Load(); n != 1 {
		t.Fatalf("profile loads = %d, want one cold fill", n)
	}
}
func TestRenderDisableDuringColdFill(t *testing.T) {
	cards := &measuredCards{entered: make(chan struct{}, 1), release: make(chan struct{})}
	service, badges := performanceService(t, cards)
	done := make(chan *RenderResult, 1)
	go func() {
		result, err := service.Render(context.Background(), RenderInput{Key: "burst-key"})
		if err != nil {
			t.Error(err)
		}
		done <- result
	}()
	<-cards.entered
	if _, err := badges.Disable(context.Background(), 7, time.Now()); err != nil {
		t.Fatal(err)
	}
	close(cards.release)
	if result := <-done; result == nil || !result.NotFound {
		t.Fatal("disabled badge escaped a slow cold fill")
	}
}
func TestRenderWaitingRequestCanCancel(t *testing.T) {
	cards := &measuredCards{entered: make(chan struct{}, 2), release: make(chan struct{})}
	service, _ := performanceService(t, cards)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = service.Render(context.Background(), RenderInput{Key: "burst-key"}) }()
	<-cards.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Render(ctx, RenderInput{Key: "burst-key"})
	close(cards.release)
	<-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting render error = %v", err)
	}
}
func BenchmarkRenderWarm(b *testing.B) {
	cards := &measuredCards{}
	service, _ := performanceService(b, cards)
	if _, err := service.Render(context.Background(), RenderInput{Key: "burst-key"}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := service.Render(context.Background(), RenderInput{Key: "burst-key"}); err != nil {
				b.Error(err)
			}
		}
	})
}
func BenchmarkRenderColdBurst(b *testing.B) {
	var loads int64
	b.ReportAllocs()
	for b.Loop() {
		cards := &measuredCards{delay: 2 * time.Millisecond}
		service, _ := performanceService(b, cards)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				if _, err := service.Render(context.Background(), RenderInput{Key: "burst-key"}); err != nil {
					b.Error(err)
				}
			})
		}
		wg.Wait()
		loads += cards.calls.Load()
	}
	b.ReportMetric(float64(loads)/float64(b.N), "profile-loads/burst")
}

func TestRenderCacheFillLanesAreBoundedAndCancellable(t *testing.T) {
	cache := newRenderCache()
	// Hold every lane, regardless of random key hashing, then verify that a
	// cancelled caller cannot create extra fill work or wait forever.
	for _, lane := range cache.fills {
		lane <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := cache.lockFill(ctx, "blocked"); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled fill did not unblock")
	}
	for _, lane := range cache.fills {
		<-lane
	}
	unlock, err := cache.lockFill(context.Background(), "blocked")
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestUnknownBadgesDoNotConsumeRenderCache(t *testing.T) {
	service := newTestService(nil, newFakeBadgeRepository(), &fakeAuditRepository{})
	for range 300 {
		result, err := service.Render(context.Background(), RenderInput{Key: "unknown"})
		if err != nil || !result.NotFound {
			t.Fatalf("unknown render: %v", err)
		}
	}
	if len(service.renderCache.entries) != 0 {
		t.Fatal("unknown keys consumed positive cache capacity")
	}
}

func TestRenderColdBurstFetchesAvatarOnce(t *testing.T) {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 64, 64))); err != nil {
		t.Fatal(err)
	}
	var fetches atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(encoded.Bytes())
	}))
	defer server.Close()
	previous := avatarHTTPClient
	avatarHTTPClient = server.Client()
	t.Cleanup(func() { avatarHTTPClient = previous })
	cards := &measuredCards{avatar: strPtr(server.URL + "/avatar.png")}
	service, _ := performanceService(t, cards)
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.AvatarHostAllowlist = []string{origin.Hostname()}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			result, renderErr := service.Render(context.Background(), RenderInput{Key: "burst-key"})
			if renderErr != nil {
				t.Error(renderErr)
				return
			}
			if !strings.Contains(string(result.SVG), "data:image/png;base64,") {
				t.Error("missing avatar")
			}
		})
	}
	wg.Wait()
	if n := fetches.Load(); n != 1 {
		t.Fatalf("avatar fetches = %d, want one", n)
	}
}

// BenchmarkAvatarColdBurst compares identical rendering work with and without
// cache-fill coalescing. The baseline deliberately starts sixteen cold fills,
// modeling a burst that reaches the old miss path before its first response.
// It is a local TLS origin and in-memory repositories, not production RPS.
func BenchmarkAvatarColdBurst(b *testing.B) {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 512, 512))); err != nil {
		b.Fatal(err)
	}
	var fetches atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetches.Add(1); _, _ = w.Write(encoded.Bytes()) }))
	defer server.Close()
	previous := avatarHTTPClient
	avatarHTTPClient = server.Client()
	b.Cleanup(func() { avatarHTTPClient = previous })
	origin, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	for _, coalesce := range []bool{false, true} {
		name := "uncoalesced"
		if coalesce {
			name = "coalesced"
		}
		b.Run(name, func(b *testing.B) {
			before := fetches.Load()
			b.ReportAllocs()
			for b.Loop() {
				cards := &measuredCards{avatar: strPtr(server.URL + "/avatar.png")}
				service, _ := performanceService(b, cards)
				service.AvatarHostAllowlist = []string{origin.Hostname()}
				service.renderCache = newRenderCache()
				var wg sync.WaitGroup
				for range 16 {
					wg.Go(func() {
						var renderErr error
						if coalesce {
							_, renderErr = service.Render(context.Background(), RenderInput{Key: "burst-key"})
						} else {
							_, renderErr = service.renderCold(context.Background(), 7, ThemeAuto, renderCacheKey("burst-key", ThemeAuto))
						}
						if renderErr != nil {
							b.Error(renderErr)
						}
					})
				}
				wg.Wait()
			}
			b.ReportMetric(float64(fetches.Load()-before)/float64(b.N), "avatar-fetches/burst")
		})
	}
}
