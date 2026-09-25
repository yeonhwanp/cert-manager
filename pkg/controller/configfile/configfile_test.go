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

package configfile

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/cert-manager/pkg/util/configfile"
)

func TestFSLoader_Load(t *testing.T) {
	expectedFilename := filepath.FromSlash("/path/to/config/file")
	const kubeConfigPath = "path/to/kubeconfig/file"

	controllerConfig := New()

	loader, err := configfile.NewConfigurationFSLoader(func(filename string) ([]byte, error) {
		if filename != expectedFilename {
			t.Fatalf("unexpected filename %q passed to ReadFile", filename)
			return nil, fmt.Errorf("unexpected filename %q", filename)
		}
		return fmt.Appendf(nil, `apiVersion: controller.config.cert-manager.io/v1alpha1
kind: ControllerConfiguration
kubeConfig: %s`, kubeConfigPath), nil
	}, expectedFilename)
	if err != nil {
		t.Fatal(err)
	}

	if err := loader.Load(controllerConfig); err != nil {
		t.Fatal(err)
	}

	// the config loader will force paths to be 'absolute' if they are provided as relative.
	absKubeConfigPath := filepath.Join(filepath.Dir(expectedFilename), kubeConfigPath)
	if controllerConfig.Config.KubeConfig != absKubeConfigPath {
		t.Errorf("expected kubeConfig to be set to %q but got %q", absKubeConfigPath, controllerConfig.Config.KubeConfig)
	}
}

func TestDecodeAndConfigureRateLimits(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		qps           float32
		burst         int
		limitsSet     bool
		errorContains string
	}{
		{name: "omitted", qps: 20, burst: 50},
		{name: "null values", config: "kubernetesAPIQPS: null\nkubernetesAPIBurst: null", qps: 20, burst: 50},
		{name: "explicit defaults", config: "kubernetesAPIQPS: 20\nkubernetesAPIBurst: 50", qps: 20, burst: 50, limitsSet: true},
		{name: "QPS only", config: "kubernetesAPIQPS: 7", qps: 7, burst: 50, limitsSet: true},
		{name: "burst only", config: "kubernetesAPIBurst: 30", qps: 20, burst: 30, limitsSet: true},
		{name: "zero values", config: "kubernetesAPIQPS: 0\nkubernetesAPIBurst: 0", limitsSet: true},
		{name: "unlimited", config: "kubernetesAPIQPS: -1", qps: -1, burst: 50, limitsSet: true},
		{name: "unknown field", config: "unknownField: true", errorContains: `unknown field "unknownField"`},
		{name: "duplicate field", config: "kubernetesAPIQPS: 7\nkubernetesAPIQPS: 20", errorContains: "already set in map"},
		{name: "invalid type", config: "kubernetesAPIQPS: invalid", errorContains: "cannot unmarshal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := New()
			err := cfg.DecodeAndConfigure([]byte("apiVersion: controller.config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\n" + tc.config))
			if tc.errorContains != "" {
				require.ErrorContains(t, err, tc.errorContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.qps, cfg.Config.KubernetesAPIQPS)
			assert.Equal(t, tc.burst, cfg.Config.KubernetesAPIBurst)
			assert.Equal(t, tc.limitsSet, cfg.KubernetesAPIRateLimitsSet)
		})
	}
}

func TestDecodeAndConfigureReplacesRateLimits(t *testing.T) {
	cfg := New()
	config := "apiVersion: controller.config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\n"
	require.NoError(t, cfg.DecodeAndConfigure([]byte(config+"kubernetesAPIQPS: 7")))
	require.True(t, cfg.KubernetesAPIRateLimitsSet)

	require.NoError(t, cfg.DecodeAndConfigure([]byte(config)))
	assert.False(t, cfg.KubernetesAPIRateLimitsSet)
	assert.Equal(t, float32(20), cfg.Config.KubernetesAPIQPS)
	assert.Equal(t, 50, cfg.Config.KubernetesAPIBurst)
}

func TestDecodeAndConfigureRejectsWrongKind(t *testing.T) {
	cfg := New()
	err := cfg.DecodeAndConfigure([]byte("apiVersion: controller.config.cert-manager.io/v1alpha1\nkind: ListOptions\n"))
	require.ErrorContains(t, err, "failed to cast object to ControllerConfiguration, unexpected type")
}
