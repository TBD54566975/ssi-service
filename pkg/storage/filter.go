package storage

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.einride.tech/aip/filtering"
)

// FilterVarsMapper is an interface that encapsulates the FilterVariablesMap method. This interface is meant to be
// implemented by any object that wants to include support for filtering.
type FilterVarsMapper interface {
	FilterVariablesMap() map[string]any
}

// IncludeFunc is a function that given a mapper object, decides whether the object should be included in the result.
type IncludeFunc func(FilterVarsMapper) (bool, error)

// NewIncludeFunc creates an IncludeFunc given a filter object.
// The result function is constructed as an evaluation of a cel program. The environment created matches standard
// construction of a filter.
// The result function runs the program evaluation on a given object that implements the FilterVarsMapper interface.
// Evaluation errors bubbled up so clients can decide what to do.
func NewIncludeFunc(filter filtering.Filter) (IncludeFunc, error) {
	if filter.CheckedExpr == nil {
		return func(_ FilterVarsMapper) (bool, error) {
			return true, nil
		}, nil
	}

	env, err := newCelEnv()
	if err != nil {
		return nil, errors.Wrap(err, "creating cel env")
	}
	ast := cel.CheckedExprToAst(filter.CheckedExpr)

	program, err := env.Program(ast)
	if err != nil {
		return nil, errors.Wrap(err, "creating program from ast")
	}
	return func(f FilterVarsMapper) (bool, error) {
		out, det, err := program.Eval(f.FilterVariablesMap())
		if err != nil {
			logrus.WithError(err).
				WithField("details", det).
				Error("evaluating submission")
			return false, errors.Wrap(err, "evaluating program")
		}
		return out.Value().(bool), nil
	}, nil
}

func simpleEquals(lhs ref.Val, rhs ref.Val) ref.Val {
	return lhs.Equal(rhs)
}

func newCelEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Function("=",
			cel.Overload("=_bool",
				[]*cel.Type{cel.BoolType, cel.BoolType},
				cel.BoolType,
				cel.BinaryBinding(simpleEquals)),
			cel.Overload("=_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(simpleEquals))))
}
