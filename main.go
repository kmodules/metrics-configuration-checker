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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	p "kmodules.xyz/client-go/tools/parser"
	"kmodules.xyz/resource-metadata/apis/meta/v1alpha1"
	"kmodules.xyz/resource-metadata/hub"
	resourcevalidator "kmodules.xyz/resource-validator"

	hp "github.com/gohugoio/hugo/parser/pageparser"
	"github.com/spf13/cobra"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	gast "github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
	"gomodules.xyz/kglog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cliflag "k8s.io/component-base/cli/flag"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	kubedbcatalog "kubedb.dev/installer/catalog"
	stashcatalog "stash.appscode.dev/installer/catalog"
)

type Location struct {
	App     string
	Version string
}

var (
	filename string
	reg      = hub.NewRegistryOfKnownResources()
	md       = goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithExtensions(Strikethrough),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(),
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
		),
	)
	logger = NewLogger(os.Stderr)
	f      cmdutil.Factory

	stashCatalog = map[Location]string{}
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "metrics-configuration-checker",
		Short: "Check schema of Kubernetes resources inside markdown code blocks",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, addon := range stashcatalog.Load().Addons {
				app := strings.ReplaceAll(addon.Name, "-", "")
				for _, v := range addon.Versions {
					stashCatalog[Location{
						App:     app,
						Version: toVersion(app, v),
					}] = v
				}
			}

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
	flags := rootCmd.Flags()
	// Normalize all flags that are coming from other packages or pre-configurations
	// a.k.a. change all "_" to "-". e.g. glog package
	flags.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)

	kubeConfigFlags := genericclioptions.NewConfigFlags(true)
	kubeConfigFlags.AddFlags(flags)
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)
	matchVersionKubeConfigFlags.AddFlags(flags)
	f = cmdutil.NewFactory(matchVersionKubeConfigFlags)

	flags.AddGoFlagSet(flag.CommandLine)

	flags.StringVar(&filename, "content", filename, "Path to directory where markdown files reside")

	kglog.Init(rootCmd, false)

	utilruntime.Must(rootCmd.Execute())
}

// CodeExtractor is a renderer.NodeRenderer implementation that
// renders Strikethrough nodes.
type CodeExtractor struct {
	html.Config
}

// NewCodeExtractor returns a new CodeExtractor.
func NewCodeExtractor(opts ...html.Option) renderer.NodeRenderer {
	r := &CodeExtractor{
		Config: html.NewConfig(),
	}
	for _, opt := range opts {
		opt.SetHTMLOption(&r.Config)
	}
	return r
}

// RegisterFuncs implements renderer.NodeRenderer.RegisterFuncs.
func (r *CodeExtractor) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindCodeBlock, r.extractCode)
	reg.Register(ast.KindFencedCodeBlock, r.extractCode)
}

func (r *CodeExtractor) extractCode(_ util.BufWriter, source []byte, n gast.Node, entering bool) (gast.WalkStatus, error) {
	if entering {
		var buf bytes.Buffer
		l := n.Lines().Len()
		for i := 0; i < l; i++ {
			line := n.Lines().At(i)
			buf.Write(line.Value(source))
		}

		err := p.ProcessResources(buf.Bytes(), checkObject)
		if err != nil && !runtime.IsMissingKind(err) && !p.IsYAMLSyntaxError(err) {
			// err
			logger.Log(err)
		}
	}
	return ast.WalkContinue, nil
}

type codeExtractor struct {
}

// Strikethrough is an extension that allow you to use codeExtractor expression like '~~text~~' .
var Strikethrough = &codeExtractor{}

func (e *codeExtractor) Extend(m goldmark.Markdown) {
	//m.Parser().AddOptions(parser.WithInlineParsers(
	//	util.Prioritized(NewStrikethroughParser(), 500),
	//))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(NewCodeExtractor(), 10),
	))
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
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		err = p.ProcessResources(content, checkObject)
		if err != nil && !runtime.IsMissingKind(err) && !p.IsYAMLSyntaxError(err) {
			return err
		}
	} else if ext == ".md" && filepath.Base(path) != "_index.md" {
		logger.Init(path)
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(content)
		page, err := hp.ParseFrontMatterAndContent(buf)
		if err != nil {
			return err
		}
		err = md.Convert(page.Content, ioutil.Discard)
		if err != nil {
			return err
		}
	}
	return nil
}

func checkObject(obj *unstructured.Unstructured) error {
	gvr, err := reg.GVR(obj.GetObjectKind().GroupVersionKind())
	if err != nil {
		return err
	}
	rd, err := reg.LoadByGVR(gvr)
	if err != nil {
		logger.Log(err)
		return nil
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	err = resourcevalidator.ValidateSchema(f, data)
	if err != nil {
		logger.Log(err)
		return nil
	}

	if rd.Spec.Validation != nil {
		validator, err := resourcevalidator.New(rd.Spec.Resource.Scope == v1alpha1.NamespaceScoped, schema.GroupVersionKind{
			Group:   rd.Spec.Resource.Group,
			Version: rd.Spec.Resource.Version,
			Kind:    rd.Spec.Resource.Kind,
		}, rd.Spec.Validation)
		if err != nil {
			return err
		}
		errList := validator.Validate(context.TODO(), obj)
		if len(errList) > 0 {
			logger.Log(errList.ToAggregate())
			return nil
		}
	}

	if gvr.Group == "kubedb.com" {
		dbVersion, _, err := unstructured.NestedString(obj.Object, "spec", "version")
		if err != nil {
			logger.Log(err)
			return nil
		}
		if dbVersion != "" && !sets.NewString(kubedbcatalog.ActiveDBVersions()[obj.GetKind()]...).Has(dbVersion) {
			logger.Log(fmt.Errorf("using unknown %s version %s", obj.GetKind(), dbVersion))
			return nil
		}
	} else if gvr.Group == "catalog.kuebdb.com" {
		if !sets.NewString(kubedbcatalog.ActiveDBVersions()[obj.GetKind()]...).Has(obj.GetName()) {
			logger.Log(fmt.Errorf("using unknown %s version %s", obj.GetKind(), obj.GetName()))
			return nil
		}
		backupTask, _, _ := unstructured.NestedString(obj.Object, "spec", "stash", "addon", "backupTask", "name")
		if err := checkStashTaskName(backupTask); err != nil {
			logger.Log(err)
			return nil
		}
		restoreTask, _, _ := unstructured.NestedString(obj.Object, "spec", "stash", "addon", "restoreTask", "name")
		if err := checkStashTaskName(restoreTask); err != nil {
			logger.Log(err)
			return nil
		}
	} else if gvr.Group == "stash.appscode.com" {
		taskName, _, err := unstructured.NestedString(obj.Object, "spec", "task", "name")
		if err != nil {
			logger.Log(err)
			return nil
		}
		if err := checkStashTaskName(taskName); err != nil {
			logger.Log(err)
			return nil
		}
	}
	return nil
}

func checkStashTaskName(taskName string) error {
	if taskName != "" && !strings.Contains(taskName, "{{<") {
		parts := strings.SplitN(taskName, "-", 3)
		if len(parts) != 3 {
			return nil // pvc-backup
		}
		loc := Location{
			App:     parts[0],
			Version: parts[2],
		}
		if _, ok := stashCatalog[loc]; !ok {
			return fmt.Errorf("%+v has no matching image tag for task %s", loc, taskName)
		}
	}
	return nil
}

func toVersion(app, v string) string {
	idx := strings.IndexRune(v, '-')
	if idx == -1 {
		return v
	}
	v2 := v[:idx]

	if app == "postgres" {
		if strings.HasPrefix(v2, "9.6.") {
			return v2
		}
		parts := strings.Split(v2, ".")
		return parts[0] + "." + parts[1]
	}
	return v2
}
