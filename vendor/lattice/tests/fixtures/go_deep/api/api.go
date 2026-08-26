package api

// Serve is the public entry surface.
func Serve() {
	process()
}

func process() {
	notDone()
}

func notDone() {
	panic("not implemented")
}

func unused() {}
