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

package v1alpha1

// PEMSizeLimitsConfig configures the maximum sizes for PEM-encoded data
// accepted by cert-manager. Limits are applied to the process-global PEM
// decoder and therefore affect every binary in the cert-manager suite.
type PEMSizeLimitsConfig struct {
	// Maximum size for a single PEM-encoded certificate (in bytes).
	// Defaults to 36500 bytes.
	MaxCertificateSize *int32 `json:"maxCertificateSize,omitempty"`

	// Maximum size for a single PEM-encoded private key (in bytes).
	// Defaults to 13000 bytes.
	MaxPrivateKeySize *int32 `json:"maxPrivateKeySize,omitempty"`

	// Maximum size for a PEM-encoded certificate chain (in bytes).
	// Defaults to 95000 bytes.
	MaxChainLength *int32 `json:"maxChainLength,omitempty"`

	// Maximum size for PEM-encoded certificate bundles (in bytes).
	// Defaults to 330000 bytes.
	MaxBundleSize *int32 `json:"maxBundleSize,omitempty"`
}
