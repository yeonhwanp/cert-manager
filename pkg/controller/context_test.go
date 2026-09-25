/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	flowcontrolapi "k8s.io/api/flowcontrol/v1"
	"k8s.io/client-go/rest"
)

func Test_NewContextFactory(t *testing.T) {
	ctxFactory, err := NewContextFactory(t.Context(), ContextOptions{
		APIServerHost:              "localhost:8443",
		KubernetesAPIQPS:           10,
		KubernetesAPIBurst:         10,
		KubernetesAPIRateLimitsSet: true,
	})
	require.NoError(t, err)

	// Ensure a single RateLimiter is preserved across Contexts.
	ctx1, err := ctxFactory.Build("test-1")
	require.NoError(t, err)
	ctx2, err := ctxFactory.Build("test-2")
	require.NoError(t, err)

	assert.NotNil(t, ctx1.RESTConfig.RateLimiter)
	assert.Same(t, ctx1.RESTConfig.RateLimiter, ctx2.RESTConfig.RateLimiter)
}

func Test_isAPFEnabled(t *testing.T) {
	testCases := []struct {
		name            string
		responseHeaders map[string]string
		statusCode      int
		expectedEnabled bool
	}{
		{
			name: "APF header present indicates enabled",
			responseHeaders: map[string]string{
				flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID: "unused-uuid",
			},
			statusCode:      http.StatusOK,
			expectedEnabled: true,
		},
		{
			name:            "no APF header indicates disabled",
			statusCode:      http.StatusOK,
			expectedEnabled: false,
		},
		{
			name: "APF header present with non-200 status still indicates enabled",
			responseHeaders: map[string]string{
				flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID: "unused-uuid",
			},
			statusCode:      http.StatusInternalServerError,
			expectedEnabled: true,
		},
		{
			name:            "no APF header with non-200 status indicates disabled",
			statusCode:      http.StatusNotFound,
			expectedEnabled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				assert.Equal(t, "/livez/ping", req.URL.Path)
				assert.Equal(t, http.MethodHead, req.Method)
				for k, v := range tc.responseHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.statusCode)
			}))
			defer server.Close()

			enabled, err := isAPFEnabled(ctx, &rest.Config{Host: server.URL})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedEnabled, enabled)
		})
	}
}

func Test_isAPFEnabled_invalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	enabled, err := isAPFEnabled(ctx, &rest.Config{Host: "://invalid"})
	assert.Error(t, err)
	assert.False(t, enabled)
}

func TestNewContextFactoryExplicitRateLimits(t *testing.T) {
	tests := []struct {
		name          string
		qps           float32
		burst         int
		expectedQPS   float32
		expectedBurst int
		unlimited     bool
	}{
		{name: "explicit defaults", qps: 20, burst: 50, expectedQPS: 20, expectedBurst: 50},
		{name: "explicit limits", qps: 7, burst: 12, expectedQPS: 7, expectedBurst: 12},
		{name: "QPS only", qps: 7, burst: 50, expectedQPS: 7, expectedBurst: 50},
		{name: "burst only", qps: 20, burst: 30, expectedQPS: 20, expectedBurst: 30},
		{name: "unlimited", qps: -1, burst: -1, expectedQPS: -1, expectedBurst: -1, unlimited: true},
		{name: "unlimited QPS only", qps: -1, burst: 50, expectedQPS: -1, expectedBurst: 50, unlimited: true},
		{name: "fractional negative", qps: -0.5, burst: 50, expectedQPS: -0.5, expectedBurst: 50, unlimited: true},
		{name: "zero QPS", qps: 0, burst: 50, expectedQPS: 5, expectedBurst: 50},
		{name: "zero burst", qps: 5, burst: 0, expectedQPS: 5, expectedBurst: 10},
		{name: "zero limits", expectedQPS: 5, expectedBurst: 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probeRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				probeRequests.Add(1)
				t.Error("explicit rate limits must not probe APF")
				w.Header().Set(flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID, "unused-uuid")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			factory, err := NewContextFactory(t.Context(), ContextOptions{
				APIServerHost:              server.URL,
				KubernetesAPIQPS:           tc.qps,
				KubernetesAPIBurst:         tc.burst,
				KubernetesAPIRateLimitsSet: true,
			})
			require.NoError(t, err)
			reconcile, err := factory.Build("controller")
			require.NoError(t, err)
			leader, err := factory.Build("leader-election")
			require.NoError(t, err)

			for _, cfg := range []*rest.Config{reconcile.RESTConfig, leader.RESTConfig} {
				assert.Equal(t, tc.expectedQPS, cfg.QPS)
				assert.Equal(t, tc.expectedBurst, cfg.Burst)
				if tc.unlimited {
					assert.Nil(t, cfg.RateLimiter)
				} else {
					require.NotNil(t, cfg.RateLimiter)
					assert.Equal(t, tc.expectedQPS, cfg.RateLimiter.QPS())
				}
			}
			// The core client also backs the event sink. All clients and
			// contexts must keep the factory's single rate limiter.
			for _, client := range []rest.Interface{
				reconcile.Client.CoreV1().RESTClient(),
				reconcile.CMClient.CertmanagerV1().RESTClient(),
				leader.Client.CoreV1().RESTClient(),
				leader.Client.CoordinationV1().RESTClient(),
			} {
				if tc.unlimited {
					assert.Nil(t, client.GetRateLimiter())
				} else {
					assert.Same(t, reconcile.RESTConfig.RateLimiter, client.GetRateLimiter())
				}
			}
			if !tc.unlimited {
				assert.Same(t, reconcile.RESTConfig.RateLimiter, leader.RESTConfig.RateLimiter)
			}
			assert.Zero(t, probeRequests.Load())
		})
	}
}

func TestNewContextFactoryAutomaticRateLimits(t *testing.T) {
	tests := []struct {
		name            string
		responseHeaders map[string]string
		expectedQPS     float32
		expectedBurst   int
		unlimited       bool
	}{
		{
			name:            "APF detected",
			responseHeaders: map[string]string{flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID: "unused-uuid"},
			expectedQPS:     -1,
			expectedBurst:   -1,
			unlimited:       true,
		},
		{name: "APF absent", expectedQPS: 20, expectedBurst: 50},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probeRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				probeRequests.Add(1)
				assert.Equal(t, http.MethodHead, req.Method)
				assert.Equal(t, "/livez/ping", req.URL.Path)
				for k, v := range tc.responseHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			factory, err := NewContextFactory(t.Context(), ContextOptions{
				APIServerHost:      server.URL,
				KubernetesAPIQPS:   20,
				KubernetesAPIBurst: 50,
			})
			require.NoError(t, err)
			reconcile, err := factory.Build("controller")
			require.NoError(t, err)
			leader, err := factory.Build("leader-election")
			require.NoError(t, err)

			for _, cfg := range []*rest.Config{reconcile.RESTConfig, leader.RESTConfig} {
				assert.Equal(t, tc.expectedQPS, cfg.QPS)
				assert.Equal(t, tc.expectedBurst, cfg.Burst)
				if tc.unlimited {
					assert.Nil(t, cfg.RateLimiter)
				} else {
					require.NotNil(t, cfg.RateLimiter)
					assert.Equal(t, tc.expectedQPS, cfg.RateLimiter.QPS())
				}
			}
			for _, client := range []rest.Interface{
				reconcile.Client.CoreV1().RESTClient(),
				reconcile.CMClient.CertmanagerV1().RESTClient(),
				leader.Client.CoreV1().RESTClient(),
				leader.Client.CoordinationV1().RESTClient(),
			} {
				if tc.unlimited {
					assert.Nil(t, client.GetRateLimiter())
				} else {
					assert.Same(t, reconcile.RESTConfig.RateLimiter, client.GetRateLimiter())
				}
			}
			if !tc.unlimited {
				assert.Same(t, reconcile.RESTConfig.RateLimiter, leader.RESTConfig.RateLimiter)
			}
			assert.EqualValues(t, 1, probeRequests.Load())
		})
	}
}

func TestNewContextFactoryUnavailableAPFServer(t *testing.T) {
	tests := []struct {
		name      string
		qps       float32
		burst     int
		limitsSet bool
	}{
		{name: "automatic limits fall back", qps: 20, burst: 50},
		{name: "explicit limits still apply", qps: 7, burst: 12, limitsSet: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.NotFoundHandler())
			server.Close()
			factory, err := NewContextFactory(t.Context(), ContextOptions{
				APIServerHost:              server.URL,
				KubernetesAPIQPS:           tc.qps,
				KubernetesAPIBurst:         tc.burst,
				KubernetesAPIRateLimitsSet: tc.limitsSet,
			})
			require.NoError(t, err)
			reconcile, err := factory.Build("controller")
			require.NoError(t, err)
			leader, err := factory.Build("leader-election")
			require.NoError(t, err)
			for _, cfg := range []*rest.Config{reconcile.RESTConfig, leader.RESTConfig} {
				assert.Equal(t, tc.qps, cfg.QPS)
				assert.Equal(t, tc.burst, cfg.Burst)
				require.NotNil(t, cfg.RateLimiter)
				assert.Equal(t, tc.qps, cfg.RateLimiter.QPS())
			}
			assert.Same(t, reconcile.RESTConfig.RateLimiter, leader.RESTConfig.RateLimiter)
			for _, client := range []rest.Interface{
				reconcile.Client.CoreV1().RESTClient(),
				reconcile.CMClient.CertmanagerV1().RESTClient(),
				leader.Client.CoreV1().RESTClient(),
				leader.Client.CoordinationV1().RESTClient(),
			} {
				assert.Same(t, reconcile.RESTConfig.RateLimiter, client.GetRateLimiter())
			}
		})
	}
}

func TestNewContextFactoryRejectsInvalidBurst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Error("explicit rate limits must not probe APF")
	}))
	defer server.Close()
	_, err := NewContextFactory(t.Context(), ContextOptions{
		APIServerHost:              server.URL,
		KubernetesAPIQPS:           5,
		KubernetesAPIBurst:         -1,
		KubernetesAPIRateLimitsSet: true,
	})
	require.ErrorContains(t, err, "burst is required to be greater than 0")
}
