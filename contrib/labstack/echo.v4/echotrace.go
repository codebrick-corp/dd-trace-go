// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

// Package echo provides functions to trace the labstack/echo package (https://github.com/labstack/echo).
package echo

import (
	"math"

	"github.com/codebrick-corp/dd-trace-go/contrib/internal/httptrace"
	"github.com/codebrick-corp/dd-trace-go/ddtrace"
	"github.com/codebrick-corp/dd-trace-go/ddtrace/ext"
	"github.com/codebrick-corp/dd-trace-go/ddtrace/tracer"
	"github.com/codebrick-corp/dd-trace-go/internal/appsec"
	"github.com/codebrick-corp/dd-trace-go/internal/log"

	"github.com/labstack/echo/v4"
)

// Middleware returns echo middleware which will trace incoming requests.
func Middleware(opts ...Option) echo.MiddlewareFunc {
	appsecEnabled := appsec.Enabled()
	cfg := new(config)
	defaults(cfg)
	for _, fn := range opts {
		fn(cfg)
	}
	log.Debug("contrib/labstack/echo.v4: Configuring Middleware: %#v", cfg)
	spanOpts := []ddtrace.StartSpanOption{
		tracer.ServiceName(cfg.serviceName),
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			request := c.Request()
			route := c.Path()
			resource := request.Method + " " + route
			opts := append(spanOpts, tracer.ResourceName(resource), tracer.Tag(ext.HTTPRoute, route))

			if !math.IsNaN(cfg.analyticsRate) {
				opts = append(opts, tracer.Tag(ext.EventSampleRate, cfg.analyticsRate))
			}

			var finishOpts []tracer.FinishOption
			if cfg.noDebugStack {
				finishOpts = []tracer.FinishOption{tracer.NoDebugStack()}
			}

			span, ctx := httptrace.StartRequestSpan(request, opts...)
			defer func() {
				httptrace.FinishRequestSpan(span, c.Response().Status, finishOpts...)
			}()

			// pass the span through the request context
			c.SetRequest(request.WithContext(ctx))
			// serve the request to the next middleware
			if appsecEnabled {
				afterMiddleware := useAppSec(c, span)
				defer afterMiddleware()
			}
			err := next(c)
			if err != nil {
				finishOpts = append(finishOpts, tracer.WithError(err))
				// invokes the registered HTTP error handler
				c.Error(err)
			}

			return err
		}
	}
}
