/*
Copyright 2025 The cert-manager Authors.

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

package pem

import (
	"strings"
	"testing"

	"github.com/go-logr/logr"

	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
)

func TestApplyGlobalSizeLimits_AppliesToGlobal(t *testing.T) {
	t.Cleanup(func() {
		SetGlobalSizeLimits(DefaultSizeLimits())
	})

	cfg := shared.PEMSizeLimitsConfig{
		MaxCertificateSize: 100000,
		MaxPrivateKeySize:  20000,
		MaxChainLength:     200000,
		MaxBundleSize:      400000,
	}

	if err := ApplyGlobalSizeLimits(cfg, logr.Discard()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := GetGlobalSizeLimits()
	if got.MaxCertificateSize != cfg.MaxCertificateSize {
		t.Errorf("MaxCertificateSize: got %d, want %d", got.MaxCertificateSize, cfg.MaxCertificateSize)
	}
	if got.MaxPrivateKeySize != cfg.MaxPrivateKeySize {
		t.Errorf("MaxPrivateKeySize: got %d, want %d", got.MaxPrivateKeySize, cfg.MaxPrivateKeySize)
	}
	if got.MaxChainLength != cfg.MaxChainLength {
		t.Errorf("MaxChainLength: got %d, want %d", got.MaxChainLength, cfg.MaxChainLength)
	}
	if got.MaxBundleSize != cfg.MaxBundleSize {
		t.Errorf("MaxBundleSize: got %d, want %d", got.MaxBundleSize, cfg.MaxBundleSize)
	}
}

// TestApplyGlobalSizeLimits_InvalidConfigRejected covers the runtime safety
// net: the same validator that runs at startup is invoked here so that values
// modified after PreRunE cannot silently bypass the constraint checks.
func TestApplyGlobalSizeLimits_InvalidConfigRejected(t *testing.T) {
	t.Cleanup(func() {
		SetGlobalSizeLimits(DefaultSizeLimits())
	})

	cfg := shared.PEMSizeLimitsConfig{
		MaxCertificateSize: 400000,
		MaxPrivateKeySize:  13000,
		MaxChainLength:     95000,
		MaxBundleSize:      330000,
	}

	err := ApplyGlobalSizeLimits(cfg, logr.Discard())
	if err == nil {
		t.Fatal("expected error for MaxCertificateSize > MaxBundleSize, got nil")
	}
	if !strings.Contains(err.Error(), "must not be larger than maxBundleSize") {
		t.Errorf("expected error to mention maxBundleSize constraint, got %q", err.Error())
	}
}
