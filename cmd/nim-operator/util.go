//go:build k8s

package main

import "k8s.io/apimachinery/pkg/util/intstr"

// intstrFromInt is a tiny wrapper around intstr.FromInt32 so the
// adapter reads left-to-right without duplicating the fully-qualified
// package path everywhere.
func intstrFromInt(i int) intstr.IntOrString {
	return intstr.FromInt(i)
}
