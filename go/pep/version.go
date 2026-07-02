package pep

// Version is the build version, stamped via -ldflags at build/image time (see the Dockerfile and the
// justfile docker-build-pep target). Defaults to "dev" for local builds.
var Version = "dev"
