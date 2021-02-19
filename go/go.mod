module nextensio/agent

go 1.15

// This ideally should need to be done only in the common repo because thats where we use gvisor
// But when we require common here, the replace statement that already exists in common does not
// seem to be honored/inherited and hence we are having to repeat it here. The gvisor lib has
// a couple of fixes required for android and hence we have forked it into our own repo and added
// the couple of fixes on top
replace gvisor.dev/gvisor v0.0.0-20201204040109-0ba39926c86f => github.com/gopakumarce/gvisor v0.0.0-20210204213648-2e0adbf0d94a

require (
	github.com/google/uuid v1.2.0
	gitlab.com/nextensio/common v0.0.0-20210219170857-d32039dc63d0
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
)
