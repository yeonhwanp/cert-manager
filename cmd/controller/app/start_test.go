/*
Copyright 2021 The cert-manager Authors.

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

package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"sync/atomic"
	"testing"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	flowcontrolapi "k8s.io/api/flowcontrol/v1"
	logsapi "k8s.io/component-base/logs/api/v1"

	"github.com/cert-manager/cert-manager/controller-binary/app/options"
)

func testCmdCommand(t *testing.T, tempDir string, yaml string, args func(string) []string) (*config.ControllerConfiguration, bool, error) {
	var tempFilePath string

	func() {
		tempFile, err := os.CreateTemp(tempDir, "config-*.yaml")
		if err != nil {
			t.Error(err)
		}
		defer tempFile.Close()

		tempFilePath = tempFile.Name()

		if _, err := tempFile.WriteString(yaml); err != nil {
			t.Error(err)
		}
	}()

	var finalConfig *config.ControllerConfiguration
	var finalLimitsSet bool

	if err := logsapi.ResetForTest(nil); err != nil {
		t.Error(err)
	}
	cmd := newServerCommand(t.Context(), func(ctx context.Context, cc *config.ControllerConfiguration, limitsSet bool) error {
		finalConfig = cc
		finalLimitsSet = limitsSet
		return nil
	}, args(tempFilePath))

	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)

	err := cmd.ExecuteContext(t.Context())
	return finalConfig, finalLimitsSet, err
}

func TestFlagsAndConfigFile(t *testing.T) {
	type testCase struct {
		yaml      string
		args      func(string) []string
		expError  bool
		expConfig func(string) *config.ControllerConfiguration
	}

	configFromDefaults := func(
		fn func(string, *config.ControllerConfiguration),
	) func(string) *config.ControllerConfiguration {
		defaults, err := options.NewControllerConfiguration()
		if err != nil {
			t.Error(err)
		}
		return func(tempDir string) *config.ControllerConfiguration {
			fn(tempDir, defaults)
			return defaults
		}
	}

	tests := []testCase{
		{
			yaml: ``,
			args: func(tempFilePath string) []string {
				return []string{"--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
kubeConfig: "<invalid>"
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--kubeconfig=valid"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = "valid"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
kubeConfig: valid
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.KubeConfig = path.Join(tempDir, "valid")
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: nil
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expError: true,
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig:
    defaultIssuerName: aaaa
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--default-issuer-kind=bbbb"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.IngressShimConfig.DefaultIssuerName = "aaaa"
				cc.IngressShimConfig.DefaultIssuerKind = "bbbb"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
logging:
    verbosity: 2
    format: text
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.Logging.Verbosity = 2
				cc.Logging.Format = "text"
			}),
		},
		{
			yaml: `
apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
ingressShimConfig: {}
`,
			args: func(tempFilePath string) []string {
				return []string{"--config=" + tempFilePath, "--extra-certificate-annotations", "venafi.cert-manager.io/custom-fields"}
			},
			expConfig: configFromDefaults(func(tempDir string, cc *config.ControllerConfiguration) {
				cc.IngressShimConfig.ExtraCertificateAnnotations = []string{"venafi.cert-manager.io/custom-fields"}
			}),
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("test-%d", i), func(t *testing.T) {
			tempDir := t.TempDir()

			config, _, err := testCmdCommand(t, tempDir, tc.yaml, tc.args)
			if tc.expError != (err != nil) {
				if err == nil {
					t.Error("expected error, got nil")
				} else {
					t.Errorf("unexpected error: %v", err)
				}
			} else if !tc.expError {
				expConfig := tc.expConfig(tempDir)
				if !reflect.DeepEqual(config, expConfig) {
					t.Errorf("expected config %v but got %v", expConfig, config)
				}
			}
		})
	}
}

func TestConfigurePEMSizeLimits(t *testing.T) {
	// Create a discarding logger for tests
	log := logr.Discard()

	tests := []struct {
		name      string
		config    *config.ControllerConfiguration
		expectErr bool
		errMsg    string
	}{
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: true,
			errMsg:    "controller configuration is nil",
		},
		{
			name: "valid configuration",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 6500,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: false,
		},
		{
			name: "zero certificate size",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 0,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: true,
			errMsg:    "maxCertificateSize must be greater than 0, got 0",
		},
		{
			name: "certificate size larger than bundle size",
			config: &config.ControllerConfiguration{
				PEMSizeLimitsConfig: config.PEMSizeLimitsConfig{
					MaxCertificateSize: 400000,
					MaxPrivateKeySize:  13000,
					MaxChainLength:     10,
					MaxBundleSize:      330000,
				},
			},
			expectErr: true,
			errMsg:    "maxCertificateSize (400000) must not be larger than maxBundleSize (330000)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := configurePEMSizeLimits(tt.config, log)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRateLimitFlagsAndConfigFile(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		flags         []string
		qps           float32
		burst         int
		limitsSet     bool
		errorContains string
	}{
		{name: "no configuration", qps: 20, burst: 50},
		{name: "empty config", config: "\n", qps: 20, burst: 50},
		{name: "null values", config: "kubernetesAPIQPS: null\nkubernetesAPIBurst: null", qps: 20, burst: 50},
		{name: "explicit CLI defaults", flags: []string{"--kube-api-qps=20", "--kube-api-burst=50"}, qps: 20, burst: 50, limitsSet: true},
		{name: "explicit file defaults", config: "kubernetesAPIQPS: 20\nkubernetesAPIBurst: 50", qps: 20, burst: 50, limitsSet: true},
		{name: "CLI QPS only", flags: []string{"--kube-api-qps=7"}, qps: 7, burst: 50, limitsSet: true},
		{name: "CLI burst only", flags: []string{"--kube-api-burst=30"}, qps: 20, burst: 30, limitsSet: true},
		{name: "file QPS only", config: "kubernetesAPIQPS: 7", qps: 7, burst: 50, limitsSet: true},
		{name: "file burst only", config: "kubernetesAPIBurst: 30", qps: 20, burst: 30, limitsSet: true},
		{name: "CLI overrides both file values", config: "kubernetesAPIQPS: 7\nkubernetesAPIBurst: 30", flags: []string{"--kube-api-qps=20", "--kube-api-burst=50"}, qps: 20, burst: 50, limitsSet: true},
		{name: "CLI QPS preserves file burst", config: "kubernetesAPIQPS: 7\nkubernetesAPIBurst: 30", flags: []string{"--kube-api-qps=20"}, qps: 20, burst: 30, limitsSet: true},
		{name: "CLI burst preserves file QPS", config: "kubernetesAPIQPS: 7\nkubernetesAPIBurst: 30", flags: []string{"--kube-api-burst=50"}, qps: 7, burst: 50, limitsSet: true},
		{name: "file QPS and CLI burst", config: "kubernetesAPIQPS: 7", flags: []string{"--kube-api-burst=30"}, qps: 7, burst: 30, limitsSet: true},
		{name: "file burst and CLI QPS", config: "kubernetesAPIBurst: 30", flags: []string{"--kube-api-qps=7"}, qps: 7, burst: 30, limitsSet: true},
		{name: "CLI QPS with empty file", config: "\n", flags: []string{"--kube-api-qps=20"}, qps: 20, burst: 50, limitsSet: true},
		{name: "CLI burst with empty file", config: "\n", flags: []string{"--kube-api-burst=50"}, qps: 20, burst: 50, limitsSet: true},
		{name: "CLI unlimited", flags: []string{"--kube-api-qps=-1"}, qps: -1, burst: 50, limitsSet: true},
		{name: "file unlimited", config: "kubernetesAPIQPS: -1\nkubernetesAPIBurst: -1", qps: -1, burst: -1, limitsSet: true},
		{name: "CLI zero", flags: []string{"--kube-api-qps=0", "--kube-api-burst=0"}, limitsSet: true},
		{name: "file zero", config: "kubernetesAPIQPS: 0\nkubernetesAPIBurst: 0", limitsSet: true},
		{name: "fractional negative", config: "kubernetesAPIQPS: -0.5", qps: -0.5, burst: 50, limitsSet: true},
		{name: "partial config still validates", config: "kubernetesAPIBurst: 10", errorContains: "must be higher or equal to kubernetesAPIQPS"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if tc.limitsSet {
					t.Error("explicit configuration must not probe APF")
				}
				assert.Equal(t, "/livez/ping", req.URL.Path)
				w.Header().Set(flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID, "unused-uuid")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			yaml := "apiVersion: controller.config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\n" + tc.config
			cc, limitsSet, err := testCmdCommand(t, t.TempDir(), yaml, func(filename string) []string {
				args := []string{"--master=" + server.URL}
				if tc.config != "" {
					args = append(args, "--config="+filename)
				}
				return append(args, tc.flags...)
			})
			if tc.errorContains != "" {
				require.ErrorContains(t, err, tc.errorContains)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cc)
			assert.Equal(t, tc.qps, cc.KubernetesAPIQPS)
			assert.Equal(t, tc.burst, cc.KubernetesAPIBurst)
			assert.Equal(t, tc.limitsSet, limitsSet)

			factory, err := buildControllerContextFactory(t.Context(), cc, limitsSet)
			require.NoError(t, err)
			controllerContext, err := factory.Build("controller")
			require.NoError(t, err)
			assert.Equal(t, tc.limitsSet, controllerContext.KubernetesAPIRateLimitsSet)
			if tc.limitsSet && tc.qps >= 0 {
				assert.NotNil(t, controllerContext.RESTConfig.RateLimiter)
			} else {
				assert.Nil(t, controllerContext.RESTConfig.RateLimiter)
			}
		})
	}
}

func TestRunRateLimits(t *testing.T) {
	tests := []struct {
		name           string
		flags          []string
		expectedProbes int32
	}{
		{name: "omitted limits probe APF", expectedProbes: 1},
		{name: "explicit limits skip APF", flags: []string{"--kube-api-qps=20", "--kube-api-burst=50"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probeRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				probeRequests.Add(1)
				assert.Equal(t, http.MethodHead, req.Method)
				assert.Equal(t, "/livez/ping", req.URL.Path)
				w.Header().Set(flowcontrolapi.ResponseHeaderMatchedFlowSchemaUID, "unused-uuid")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			require.NoError(t, logsapi.ResetForTest(nil))
			// Stop after client construction, before starting servers or controllers.
			args := append([]string{"--master=" + server.URL, "--metrics-listen-address=invalid-address"}, tc.flags...)
			cmd := newServerCommand(t.Context(), Run, args)
			cmd.SetErr(io.Discard)
			cmd.SetOut(io.Discard)

			err := cmd.ExecuteContext(t.Context())
			require.ErrorContains(t, err, "failed to listen on prometheus address invalid-address")
			assert.Equal(t, tc.expectedProbes, probeRequests.Load())
		})
	}
}
