package testutil

import (
	"context"
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StartRedis starts an isolated Redis 8 instance and returns a connected client.
func StartRedis(t *testing.T) *goredis.Client {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:8-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start Redis container: %v", err)
	}

	t.Cleanup(func() {
		terminateErr := testcontainers.TerminateContainer(container)
		if terminateErr != nil {
			t.Errorf("terminate Redis container: %v", terminateErr)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get Redis host: %v", err)
	}
	port, err := container.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatalf("get Redis mapped port: %v", err)
	}

	client := goredis.NewClient(&goredis.Options{Addr: host + ":" + port.Port()})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		t.Fatalf("ping Redis: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close Redis client: %v", err)
		}
	})
	return client
}
