/*
Copyright 2018 The Kubernetes Authors.

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

package resourcevalidator

import (
	"context"
	"fmt"

	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structurallisttype "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	schemaobjectmeta "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/objectmeta"
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kube-openapi/pkg/validation/validate"
)

type customResourceValidator struct {
	namespaceScoped   bool
	kind              schema.GroupVersionKind
	schemaValidator   *validate.SchemaValidator
	structuralSchemas *structuralschema.Structural
}

func nameValidator(gvk schema.GroupVersionKind) func(_ string, _ bool) []string {
	if gvk.Group == "rbac.authorization.k8s.io" {
		return func(name string, prefix bool) []string {
			return nil
		}
	}
	return validation.NameIsDNSSubdomain
}

func (a customResourceValidator) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return field.ErrorList{field.Invalid(field.NewPath(""), u, fmt.Sprintf("has type %T. Must be a pointer to an Unstructured type", u))}
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return field.ErrorList{field.Invalid(field.NewPath("metadata"), nil, err.Error())}
	}

	if errs := a.ValidateTypeMeta(ctx, u); len(errs) > 0 {
		return errs
	}

	var allErrs field.ErrorList

	allErrs = append(allErrs, validation.ValidateObjectMetaAccessor(accessor, a.namespaceScoped, nameValidator(obj.GetObjectKind().GroupVersionKind()), field.NewPath("metadata"))...)
	allErrs = append(allErrs, apiservervalidation.ValidateCustomResource(nil, u.UnstructuredContent(), a.schemaValidator)...)

	// validate embedded resources
	if u, ok := obj.(*unstructured.Unstructured); ok {
		allErrs = append(allErrs, schemaobjectmeta.Validate(nil, u.Object, a.structuralSchemas, false)...)

		// validate x-kubernetes-list-type "map" and "set" invariant
		allErrs = append(allErrs, structurallisttype.ValidateListSetsAndMaps(nil, a.structuralSchemas, u.Object)...)
	}

	return allErrs
}

func (a customResourceValidator) ValidateTypeMeta(ctx context.Context, obj *unstructured.Unstructured) field.ErrorList {
	typeAccessor, err := meta.TypeAccessor(obj)
	if err != nil {
		return field.ErrorList{field.Invalid(field.NewPath("kind"), nil, err.Error())}
	}

	var allErrs field.ErrorList
	if typeAccessor.GetKind() != a.kind.Kind {
		allErrs = append(allErrs, field.Invalid(field.NewPath("kind"), typeAccessor.GetKind(), fmt.Sprintf("must be %v", a.kind.Kind)))
	}

	apiVersion := a.kind.Version
	if a.kind.Group != "" {
		apiVersion = a.kind.Group + "/" + a.kind.Version
	}
	if typeAccessor.GetAPIVersion() != apiVersion {
		allErrs = append(allErrs, field.Invalid(field.NewPath("apiVersion"), typeAccessor.GetAPIVersion(), fmt.Sprintf("must be %v", a.kind.Group+"/"+a.kind.Version)))
	}
	return allErrs
}
