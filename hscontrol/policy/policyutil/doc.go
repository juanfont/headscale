// Package policyutil contains pure functions that transform compiled
// policy rules for a specific node. The headline function is
// ReduceFilterRules, which filters global rules down to those relevant
// to one node.
//
// A node's SubnetRoutes (approved, non-exit) participate in rule
// matching so subnet routers receive filter rules for destinations
// their subnets cover — the fix for issue #3169.
package policyutil
