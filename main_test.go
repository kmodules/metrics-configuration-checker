/*
Copyright AppsCode Inc. and Contributors

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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ExecuteCommand(t *testing.T) {
	t.Parallel()
	rootCmd := NewRootCmd()
	Initialize(rootCmd)

	// test all valid metrics configuration manifest files from a directory
	rootCmd.SetArgs([]string{"--content", "./examples/valid"})
	err := rootCmd.Execute()
	require.NoError(t, err)

	// test individual valid metrics configuration manifest files
	rootCmd.SetArgs([]string{"--content", "./examples/valid/pod-config.yaml"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	rootCmd.SetArgs([]string{"--content", "./examples/valid/sts-config.yaml"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	rootCmd.SetArgs([]string{"--content", "./examples/valid/dpl-config.yaml"})
	err = rootCmd.Execute()
	require.NoError(t, err)

	// test invalid metrics configuration manifest files which should produce error
	rootCmd.SetArgs([]string{"--content", "./examples/invalid/pod-error-config.yaml"})
	err = rootCmd.Execute()
	require.Error(t, err)

	rootCmd.SetArgs([]string{"--content", "./examples/invalid/dpl-error-config.yaml"})
	err = rootCmd.Execute()
	require.Error(t, err)

	rootCmd.SetArgs([]string{"--content", "./examples/invalid/sts-error-config.yaml"})
	err = rootCmd.Execute()
	require.Error(t, err)
}
