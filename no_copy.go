package noise

// noCopy is recognized by go vet's copylocks analyzer.
// Embed it in stateful types that must not be copied after first use.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
