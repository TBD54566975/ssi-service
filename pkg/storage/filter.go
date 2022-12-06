package storage

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.einride.tech/aip/filtering"
)

type foo interface {
	FilterVariablesMap() map[string]interface{}
}

type IncludeFunc func(foo) bool

func Evaluator(filter filtering.Filter) (IncludeFunc, error) {
	if filter.CheckedExpr == nil {
		return func(_ foo) bool {
			return true
		}, nil
	}

	env, err := Env()
	if err != nil {
		return nil, errors.Wrap(err, "creating cel env")
	}
	ast := cel.CheckedExprToAst(filter.CheckedExpr)

	program, err := env.Program(ast)
	if err != nil {
		return nil, errors.Wrap(err, "creating program from ast")
	}
	return func(f foo) bool {
		out, det, err := program.Eval(f.FilterVariablesMap())
		if err != nil {
			logrus.WithError(err).
				WithField("details", det).
				Error("evaluating submission")
			panic(err)
		}
		return out.Value() == true
	}, nil
}

func Env() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Function("=",
			cel.Overload("=_bool",
				[]*cel.Type{cel.BoolType, cel.BoolType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					return lhs.Equal(rhs)
				})),
			cel.Overload("=_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs ref.Val, rhs ref.Val) ref.Val {
					return lhs.Equal(rhs)
				}))))
}
