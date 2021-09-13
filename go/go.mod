module nextensio/agent

go 1.15

// This ideally should need to be done only in the common repo because thats where we use gvisor
// But when we require common here, the replace statement that already exists in common does not
// seem to be honored/inherited and hence we are having to repeat it here. The gvisor lib has
// a couple of fixes required for android and hence we have forked it into our own repo and added
// the couple of fixes on top
replace gvisor.dev/gvisor v0.0.0-20201204040109-0ba39926c86f => github.com/nextensio/gvisor v0.0.0-20210204213648-2e0adbf0d94a

require (
	github.com/google/uuid v1.2.0
	github.com/opentracing/opentracing-go v1.2.0
	github.com/uber/jaeger-client-go v2.29.1+incompatible
	github.com/uber/jaeger-lib v2.4.1+incompatible
	gitlab.com/nextensio/common/go v0.0.0-20210913130917-5662813d60d3
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
)
