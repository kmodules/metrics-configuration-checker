package resourcevalidator

import (
	"context"
	"fmt"

	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"

	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Validator interface {
	Validate(ctx context.Context, obj runtime.Object) field.ErrorList
	ValidateTypeMeta(ctx context.Context, obj *unstructured.Unstructured) field.ErrorList
}

func New(namespaceScoped bool, kind schema.GroupVersionKind, validationSchema *apiextensionsv1.CustomResourceValidation) (Validator, error) {
	var internalValidationSchema *apiextensionsinternal.CustomResourceValidation
	if validationSchema != nil {
		internalValidationSchema = &apiextensionsinternal.CustomResourceValidation{}
		if err := apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(validationSchema, internalValidationSchema, nil); err != nil {
			return nil, fmt.Errorf("failed to convert CRD validation to internal version: %v", err)
		}
	}
	schemaValidator, _, err := apiservervalidation.NewSchemaValidator(internalValidationSchema)
	if err != nil {
		return nil, err
	}

	s, err := structuralschema.NewStructural(internalValidationSchema.OpenAPIV3Schema)
	if err != nil {
		// This should never happen. If it does, it is a programming error.
		utilruntime.HandleError(fmt.Errorf("failed to convert schema to structural: %v", err))
		return nil, fmt.Errorf("the server could not properly serve the CR schema") // validation should avoid this
	}

	// we don't own s completely, e.g. defaults are not deep-copied. So better make a copy here.
	s = s.DeepCopy()

	if err := structuraldefaulting.PruneDefaults(s); err != nil {
		// This should never happen. If it does, it is a programming error.
		utilruntime.HandleError(fmt.Errorf("failed to prune defaults: %v", err))
		return nil, fmt.Errorf("the server could not properly serve the CR schema") // validation should avoid this
	}

	return &customResourceValidator{
		namespaceScoped:   namespaceScoped,
		kind:              kind,
		schemaValidator:   schemaValidator,
		structuralSchemas: s,
	}, nil
}
