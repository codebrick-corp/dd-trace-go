// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

// Package httptrace provides functionalities to trace HTTP requests that are commonly required and used across
// contrib/** integrations.
package httptrace

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"inet.af/netaddr"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	ipv6SpecialNetworks = []*netaddr.IPPrefix{
		ippref("fec0::/10"), // site local
	}
	defaultIPHeaders = []string{
		"x-forwarded-for",
		"x-real-ip",
		"x-client-ip",
		"x-forwarded",
		"x-cluster-client-ip",
		"forwarded-for",
		"forwarded",
		"via",
		"true-client-ip",
	}
	cfg = newConfig()
)

// StartRequestSpan starts an HTTP request span with the standard list of HTTP request span tags (http.method, http.url,
// http.useragent). Any further span start option can be added with opts.
func StartRequestSpan(r *http.Request, opts ...ddtrace.StartSpanOption) (tracer.Span, context.Context) {
	// Append our span options before the given ones so that the caller can "overwrite" them.
	opts = append([]ddtrace.StartSpanOption{
		tracer.SpanType(ext.SpanTypeWeb),
		tracer.Tag(ext.HTTPMethod, r.Method),
		tracer.Tag(ext.HTTPURL, r.URL.Path),
		tracer.Tag(ext.HTTPUserAgent, r.UserAgent()),
		tracer.Measured(),
	}, opts...)
	for k, v := range getURLSpanTags(r) {
		opts = append([]ddtrace.StartSpanOption{tracer.Tag(k, v)}, opts...)
	}
	if r.Host != "" {
		opts = append([]ddtrace.StartSpanOption{
			tracer.Tag("http.host", r.Host),
		}, opts...)
	}
	if ip := getClientIP(r); ip.IsValid() {
		opts = append(opts, tracer.Tag(ext.HTTPClientIP, ip.String()))
	}
	if spanctx, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header)); err == nil {
		opts = append(opts, tracer.ChildOf(spanctx))
	}
	return tracer.StartSpanFromContext(r.Context(), "http.request", opts...)
}

// FinishRequestSpan finishes the given HTTP request span and sets the expected response-related tags such as the status
// code. Any further span finish option can be added with opts.
func FinishRequestSpan(s tracer.Span, status int, opts ...tracer.FinishOption) {
	var statusStr string
	if status == 0 {
		statusStr = "200"
	} else {
		statusStr = strconv.Itoa(status)
	}
	s.SetTag(ext.HTTPCode, statusStr)
	if status >= 500 && status < 600 {
		s.SetTag(ext.Error, fmt.Errorf("%s: %s", statusStr, http.StatusText(status)))
	}
	s.Finish(opts...)
}

// ippref returns the IP network from an IP address string s. If not possible, it returns nil.
func ippref(s string) *netaddr.IPPrefix {
	if prefix, err := netaddr.ParseIPPrefix(s); err == nil {
		return &prefix
	}
	return nil
}

// getClientIP attempts to find the client IP address in the given request r.
func getClientIP(r *http.Request) netaddr.IP {
	ipHeaders := defaultIPHeaders
	if len(cfg.clientIPHeader) > 0 {
		ipHeaders = []string{cfg.clientIPHeader}
	}
	check := func(s string) netaddr.IP {
		for _, ipstr := range strings.Split(s, ",") {
			ip := parseIP(strings.TrimSpace(ipstr))
			if !ip.IsValid() {
				continue
			}
			if isGlobal(ip) {
				return ip
			}
		}
		return netaddr.IP{}
	}
	for _, hdr := range ipHeaders {
		if v := r.Header.Get(hdr); v != "" {
			if ip := check(v); ip.IsValid() {
				return ip
			}
		}
	}
	if remoteIP := parseIP(r.RemoteAddr); remoteIP.IsValid() && isGlobal(remoteIP) {
		return remoteIP
	}
	return netaddr.IP{}
}

func parseIP(s string) netaddr.IP {
	if ip, err := netaddr.ParseIP(s); err == nil {
		return ip
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		if ip, err := netaddr.ParseIP(h); err == nil {
			return ip
		}
	}
	return netaddr.IP{}
}

func isGlobal(ip netaddr.IP) bool {
	// IsPrivate also checks for ipv6 ULA.
	// We care to check for these addresses are not considered public, hence not global.
	// See https://www.rfc-editor.org/rfc/rfc4193.txt for more details.
	isGlobal := !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	if !isGlobal || !ip.Is6() {
		return isGlobal
	}
	for _, n := range ipv6SpecialNetworks {
		if n.Contains(ip) {
			return false
		}
	}
	return isGlobal
}

// getURLSpanTags generates the list of standard span tags related to http.url and http.url_details.*
// For more information see https://datadoghq.atlassian.net/wiki/spaces/APM/pages/2357395856/Span+attributes#http.url
func getURLSpanTags(r *http.Request) map[string]string {
	// Quoting net/http comments about net.Request.URL:
	// "For most requests, fields other than Path and RawQuery will be
	// empty. (See RFC 7230, Section 5.3)"
	// This is why we don't rely on url.URL.String(), url.URL.Host, url.URL.Scheme, etc...
	scheme := "http"
	port := "80"
	host := r.Host
	path := r.URL.EscapedPath()
	var url strings.Builder
	if r.TLS != nil {
		scheme = "https"
		port = "443"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}
	for _, str := range []string{scheme, "://", host, path} {
		url.WriteString(str)
	}
	tags := map[string]string{
		ext.HTTPURLHost:   host,
		ext.HTTPURLPath:   path,
		ext.HTTPURLScheme: scheme,
		ext.HTTPURLPort:   port,
	}
	// Return early if no query string found or if obfuscation is disabled
	if r.URL.RawQuery == "" || cfg.queryStringObfRegexp == nil {
		tags[ext.HTTPURL] = url.String()
		return tags
	}
	// Obfuscate the query string before building the final URL
	// https://datadoghq.atlassian.net/wiki/spaces/APS/pages/2490990623/QueryString+-+Sensitive+Data+Obfuscation
	query := cfg.queryStringObfRegexp.ReplaceAllLiteralString(r.URL.RawQuery, "<redacted>")
	tags[ext.HTTPURLQueryString] = query
	url.WriteString("?")
	url.WriteString(query)
	tags[ext.HTTPURL] = url.String()
	return tags
}
