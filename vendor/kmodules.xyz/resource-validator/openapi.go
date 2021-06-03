package resourcevalidator

import (
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	openapivalidation "k8s.io/kubectl/pkg/util/openapi/validation"
	"k8s.io/kubectl/pkg/validation"
)

func ValidateSchema(f cmdutil.Factory, obj []byte) error {
	resources, err := f.OpenAPISchema()
	if err != nil {
		return err
	}

	schema := validation.ConjunctiveSchema{
		openapivalidation.NewSchemaValidation(resources),
		validation.NoDoubleKeySchema{},
	}
	return schema.ValidateBytes(obj)
}
