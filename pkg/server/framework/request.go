package framework

import (
	"errors"
	"github.com/goccy/go-json"
	"net/http"
	"reflect"
	"strings"

	"github.com/dimfeld/httptreemux/v5"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"gopkg.in/go-playground/validator.v9"
	entranslations "gopkg.in/go-playground/validator.v9/translations/en"
)

// validate holds the settings and caches for validating request payloads.
var validate *validator.Validate

// translator is a cache of locale and translation information.
var translator *ut.UniversalTranslator

func init() {
	// Instantiate validator.
	validate = validator.New()

	// Instantiate the english locale for the validator lib.
	enLocale := en.New()

	// Create a translator using english as the fallback locale (first arg).
	// Provide one or more arguments for additional supported locale.
	translator = ut.New(enLocale, enLocale)

	// Register english error messages for validation errors.
	lang, _ := translator.GetTranslator("en")
	_ = entranslations.RegisterDefaultTranslations(validate, lang)

	// Use JSON tag names for errors instead of Go struct field names
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}

		return name
	})
}

// RouteParams returns a map of route params and their respective values.
// e.g. route: /users/:id  request: /users/1 map: :id -> 1
func RouteParams(r *http.Request) map[string]string {
	//! TODO: why am i passing context into here?
	return httptreemux.ContextParams(r.Context())
}

// Decode reads an HTTP request body looking for a JSON document.
// The body is decoded into the value provided.
//
// The provided value is checked for validation tags if it's a struct.
func Decode(r *http.Request, val interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(val); err != nil {
		return NewRequestError(err, http.StatusBadRequest)
	}

	if err := validate.Struct(val); err != nil {
		vErrors, ok := err.(validator.ValidationErrors)
		if !ok {
			return err
		}

		// lang is the language used for error messages.
		//* use value of "Accept-Language" header when more than one
		//* language is supported
		lang, _ := translator.GetTranslator("en")

		var fieldErrors []FieldError
		for _, vError := range vErrors {
			fieldError := FieldError{
				Field: vError.Field(),
				Error: vError.Translate(lang),
			}

			fieldErrors = append(fieldErrors, fieldError)
		}

		return &SafeError{
			Err:        errors.New("field validation error"),
			StatusCode: http.StatusBadRequest,
			Fields:     fieldErrors,
		}
	}

	return nil
}
