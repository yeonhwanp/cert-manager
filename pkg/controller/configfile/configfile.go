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

	"k8s.io/apimachinery/pkg/runtime/serializer"

	config "github.com/cert-manager/cert-manager/internal/apis/config/controller"
	"github.com/cert-manager/cert-manager/internal/apis/config/controller/scheme"
	configv1alpha1 "github.com/cert-manager/cert-manager/pkg/apis/config/controller/v1alpha1"
)

type ControllerConfigFile struct {
	Config *config.ControllerConfiguration

	// KubernetesAPIRateLimitsSet records explicit file settings before defaulting.
	KubernetesAPIRateLimitsSet bool
}

func New() *ControllerConfigFile {
	return &ControllerConfigFile{
		Config: &config.ControllerConfiguration{},
	}
}

func decodeConfiguration(data []byte) (*config.ControllerConfiguration, bool, error) {
	s, codec, err := scheme.NewSchemeAndCodecs(serializer.EnableStrict)
	if err != nil {
		return nil, false, err
	}

	obj, _, err := codec.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode: %w", err)
	}

	versioned, ok := obj.(*configv1alpha1.ControllerConfiguration)
	if !ok {
		return nil, false, fmt.Errorf("failed to cast object to ControllerConfiguration, unexpected type")
	}

	limitsSet := versioned.KubernetesAPIQPS != nil || versioned.KubernetesAPIBurst != nil
	s.Default(versioned)
	c := &config.ControllerConfiguration{}
	if err := s.Convert(versioned, c, nil); err != nil {
		return nil, false, fmt.Errorf("failed to convert: %w", err)
	}
	return c, limitsSet, nil
}

func (cfg *ControllerConfigFile) DecodeAndConfigure(data []byte) error {
	config, limitsSet, err := decodeConfiguration(data)
	if err != nil {
		return err
	}
	cfg.Config = config
	cfg.KubernetesAPIRateLimitsSet = limitsSet

	return nil
}

func (cfg *ControllerConfigFile) GetPathRefs() ([]*string, error) {
	paths, err := ControllerConfigurationPathRefs(cfg.Config)
	if err != nil {
		return nil, err
	}
	return paths, err

}

// ControllerConfigurationPathRefs returns pointers to all the ControllerConfiguration fields that contain filepaths.
// You might use this, for example, to resolve all relative paths against some common root before
// passing the configuration to the application. This method must be kept up to date as new fields are added.
func ControllerConfigurationPathRefs(cfg *config.ControllerConfiguration) ([]*string, error) {

	return []*string{
		&cfg.KubeConfig,
	}, nil
}
