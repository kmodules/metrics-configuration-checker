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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	p "kmodules.xyz/client-go/tools/parser"
	"kmodules.xyz/resource-metadata/hub"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gomodules.xyz/logs"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	filename string
	reg      = hub.NewRegistryOfKnownResources()
	logger   = NewLogger(os.Stderr)
	kc       = MustClient()
)

const (
	MetricsConfigurationKind = "MetricsConfiguration"
)

func NewRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "metrics-configuration-checker",
		Short: "Check schema of MetricsConfiguration resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := os.Stat(filename)
			if os.IsNotExist(err) {
				return err
			}
			if info.IsDir() {
				err = filepath.Walk(filename, check)
				if err != nil {
					return err
				}
			} else {
				err = check(filename, info, nil)
				if err != nil {
					return err
				}
			}

			return logger.Result()
		},
	}
}

func main() {
	rootCmd := NewRootCmd()

	flags := rootCmd.Flags()
	flags.StringVar(&filename, "content", filename, "Path to directory where metrics configurations files reside")

	logs.Init(rootCmd, false)
	utilruntime.Must(rootCmd.Execute())
}

func check(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	ext := filepath.Ext(info.Name())
	if ext == ".yaml" || ext == ".yml" || ext == ".json" {
		logger.Init(path)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		err = p.ProcessResources(content, checkMetricsConfigObject)
		if err != nil && !runtime.IsMissingKind(err) && !p.IsYAMLSyntaxError(err) {
			return err
		}
		if !logger.errFound {
			fmt.Printf("Checked file: %s, Status: OK\n", info.Name())
		}
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "skipped file: %s\n", path)
	}
	return nil
}

func NewClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)

	ctrl.SetLogger(klogr.New())
	cfg := ctrl.GetConfigOrDie()
	cfg.QPS = 100
	cfg.Burst = 100

	mapper, err := apiutil.NewDynamicRESTMapper(cfg)
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{
		Scheme: scheme,
		Mapper: mapper,
		//Opts: client.WarningHandlerOptions{
		//	SuppressWarnings:   false,
		//	AllowDuplicateLogs: false,
		//},
	})
}

func MustClient() client.Client {
	kc, err := NewClient()
	if err != nil {
		panic(err)
	}
	return kc
}

func isValidJsonPath(schema *v1.JSONSchemaProps, jsonPath string) error {
	if jsonPath == "." {
		return nil
	}
	generateError := true
	fields := strings.Split(jsonPath, ".")
	fields = fields[1:]
	currSchema := *schema
	if len(fields) > 0 && (fields[0] == "status" || fields[0] == "metadata") {
		generateError = false
	}
	for _, field := range fields {
		if strings.Contains(field, "[*]") {
			arrayField := strings.TrimSuffix(field, "[*]")
			val, ok := currSchema.Properties[arrayField]
			if !ok && currSchema.Properties == nil && currSchema.Type == "object" {
				generateError = false
			}
			if !ok {
				if generateError {
					return errors.Errorf("json path %q doesn't exist", jsonPath)
				}
				// klog.Infof("json path %q doesn't exist in resource descriptor", jsonPath)
				break
			}
			currSchema = *val.Items.Schema
		} else if val, ok := currSchema.Properties[field]; ok {
			currSchema = val
		} else {
			if currSchema.Properties == nil && currSchema.Type == "object" {
				generateError = false
			}
			if generateError {
				return errors.Errorf("json path %q doesn't exist", jsonPath)
			}
			// klog.Infof("json path %q doesn't exist in resource descriptor", jsonPath)
			break
		}
	}
	return nil
}

func checkMetricsConfigObject(ri p.ResourceInfo) error {
	obj := ri.Object.DeepCopy()

	objKind := obj.GetKind()
	if objKind != MetricsConfigurationKind {
		return nil
	}

	// get metrics configurations object .spec.targetRef field
	targetRef, ok, err := unstructured.NestedStringMap(obj.Object, "spec", "targetRef")
	if err != nil {
		logger.Log(err)
		return nil
	} else if !ok {
		logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: targetRef is missing in MetricsConfiguration Spec", objKind))
		return nil
	} else if targetRef["apiVersion"] == "" || targetRef["kind"] == "" {
		logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: targetRef is missing in MetricsConfiguration Spec", objKind))
		return nil
	}

	gv, err := schema.ParseGroupVersion(targetRef["apiVersion"])
	if err != nil {
		logger.Log(err)
		return nil
	}

	gvk := schema.GroupVersionKind{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    targetRef["kind"],
	}
	mapping, err := kc.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		logger.Log(err)
		return nil
	}

	var crdSchema *v1.JSONSchemaProps

	var crd v1.CustomResourceDefinition
	crdName := fmt.Sprintf("%s.%s", mapping.Resource.Resource, mapping.Resource.Group)
	err = kc.Get(context.TODO(), client.ObjectKey{Name: crdName}, &crd)
	if apierrors.IsNotFound(err) {
		// get resource descriptor from groupVersionResource
		rd, err := reg.LoadByGVR(mapping.Resource)
		if err != nil {
			logger.Log(err)
			return nil
		}
		crdSchema = rd.Spec.Validation.OpenAPIV3Schema
	} else if err != nil {
		logger.Log(err)
		return nil
	} else {
		for _, v := range crd.Spec.Versions {
			if v.Name == gvk.Version && v.Schema != nil {
				crdSchema = v.Schema.OpenAPIV3Schema
			}
		}
	}
	if crdSchema == nil {
		logger.Log(fmt.Errorf("missing schema for %+v", gvk))
		return nil
	}

	// get metrics list
	metrics, ok, err := unstructured.NestedSlice(obj.Object, "spec", "metrics")
	if err != nil || !ok {
		logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: no metrics is specified", objKind))
		return nil
	}

	// looping over the metrics list and check json paths
	for _, m := range metrics {
		met := m.(map[string]interface{})

		// check Field path
		if met["field"] != nil {
			field := met["field"].(map[string]interface{})
			if field["path"] != nil {
				err = isValidJsonPath(crdSchema, field["path"].(string))
				if err != nil {
					logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: %s", objKind, err.Error()))
				}
			}
		}

		// check Label's json path
		if met["labels"] != nil {
			labels := met["labels"].([]interface{})
			for _, l := range labels {
				labelFields := l.(map[string]interface{})
				if labelFields["valuePath"] != nil {
					err = isValidJsonPath(crdSchema, labelFields["valuePath"].(string))
					if err != nil {
						logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: %s", objKind, err.Error()))
					}
				}
			}
		}

		// check Parameter's json path
		if met["params"] != nil {
			params := met["params"].([]interface{})
			for _, par := range params {
				paramFields := par.(map[string]interface{})
				if paramFields["valuePath"] != nil {
					err = isValidJsonPath(crdSchema, paramFields["valuePath"].(string))
					if err != nil {
						logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: %s", objKind, err.Error()))
					}
				}
			}
		}

		// check metric value json path
		if met["metricValue"] != nil {
			metricValCfg := met["metricValue"].(map[string]interface{})
			if metricValCfg["valueFromPath"] != nil {
				err = isValidJsonPath(crdSchema, metricValCfg["valueFromPath"].(string))
				if err != nil {
					logger.Log(fmt.Errorf("status: check has been failed for resource %q. reason: %s", objKind, err.Error()))
				}
			}
		}

	}
	return nil
}
