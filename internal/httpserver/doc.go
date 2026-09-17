// Package httpserver builds the four independently-routed HTTP muxes the
// service exposes (spec section 2): Public, Admin, Auth, and Ops. Every
// route this milestone doesn't implement yet returns 501, but it still
// exists on its correct listener and nowhere else -- see
// httpserver_test.go and integration_test.go for what "nowhere else" means
// in practice.
package httpserver
