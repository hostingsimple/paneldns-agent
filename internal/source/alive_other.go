//go:build !unix

package source

// processAlive is not supported off Unix; the agent runs only on Linux.
func processAlive(int) Running { return RunningUnknown }
