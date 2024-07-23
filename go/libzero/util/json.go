package util

import (
	"encoding/json"

	"github.com/go-playground/validator/v10"
)

func AnyToStruct[T any](obj interface{}) (*T, error) {
	var err error
	var asJson []byte
	asJson, ok := obj.([]byte)
	if !ok {
		asJson, err = json.Marshal(obj)
		if err != nil {
			return nil, err
		}
	}
	var result T
	err = json.Unmarshal(asJson, &result)
	if err != nil {
		return nil, err
	}
	validate := validator.New()
	err = validate.Struct(result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
