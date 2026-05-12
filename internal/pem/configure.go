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
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/cert-manager/cert-manager/internal/apis/config/shared"
	sharedvalidation "github.com/cert-manager/cert-manager/internal/apis/config/shared/validation"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

// ApplyGlobalSizeLimits validates the supplied PEM size limits and, on success,
// applies them to the process-global PEM decoder via SetGlobalSizeLimits.
// The same validator that runs during config validation is used here as a
// runtime safety net.
func ApplyGlobalSizeLimits(cfg shared.PEMSizeLimitsConfig, log logr.Logger) error {
	if errs := sharedvalidation.ValidatePEMSizeLimitsConfig(&cfg, field.NewPath("pemSizeLimitsConfig")); len(errs) > 0 {
		return fmt.Errorf("invalid PEM size limits: %w", errs.ToAggregate())
	}

	limits := NewSizeLimitsFromConfig(
		cfg.MaxCertificateSize,
		cfg.MaxPrivateKeySize,
		cfg.MaxChainLength,
		cfg.MaxBundleSize,
	)
	SetGlobalSizeLimits(limits)

	log.V(logf.InfoLevel).Info("configured PEM size limits",
		"maxCertificateSize", limits.MaxCertificateSize,
		"maxPrivateKeySize", limits.MaxPrivateKeySize,
		"maxChainLength", limits.MaxChainLength,
		"maxBundleSize", limits.MaxBundleSize)

	return nil
}
