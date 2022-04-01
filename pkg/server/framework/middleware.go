package framework

// Middleware is a function that provides the ability to run some code before and/or
// after a Handler. The motivation behind writing middleware functions is to
// remove repeated or boilerplate code that is either not the direct concern
// of a given handler OR code that seems to be repeated across many handlers.
type Middleware func(handler Handler) Handler

// WrapMiddleware returns a new handler that is the result of wrapping all
// provided middlewares around the provided handler. Think of it like an onion.
// Middlewares will execute in the order they are provided
func WrapMiddleware(mw []Middleware, handler Handler) Handler {
	// wrap the provided middlewares around the provided handler from
	// back to front so that the order provided is the order of execution
	for i := len(mw) - 1; i >= 0; i-- {
		h := mw[i]

		if h != nil {
			handler = h(handler)
		}
	}

	return handler
}
