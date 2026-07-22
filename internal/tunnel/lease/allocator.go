package lease

import (
	"fmt"
	"net"
)

// portAllocator hands out ports from an inclusive [min, max] range, skipping
// ports already bound at allocation time as a safety net against colliding with
// another local service. Not safe for concurrent use; callers hold Store.mu.
type portAllocator struct {
	min  int
	max  int
	next int
	used map[int]bool
}

func newPortAllocator(min, max int) *portAllocator {
	return &portAllocator{min: min, max: max, next: min, used: make(map[int]bool)}
}

// reserve marks a port as in use (used when rehydrating leases on startup).
func (a *portAllocator) reserve(port int) {
	if port >= a.min && port <= a.max {
		a.used[port] = true
	}
}

// release returns a port to the free pool.
func (a *portAllocator) release(port int) {
	delete(a.used, port)
}

// free returns the number of unreserved ports remaining.
func (a *portAllocator) free() int {
	return (a.max - a.min + 1) - len(a.used)
}

// allocate returns the next free port, probing each candidate to skip any port
// that is already listening.
func (a *portAllocator) allocate() (int, error) {
	span := a.max - a.min + 1
	for i := 0; i < span; i++ {
		port := a.next
		a.next++
		if a.next > a.max {
			a.next = a.min
		}
		if a.used[port] {
			continue
		}
		if portInUse(port) {
			a.used[port] = true // avoid re-probing a foreign listener every allocate
			continue
		}
		a.used[port] = true
		return port, nil
	}
	return 0, ErrPortsExhausted
}

// portInUse reports whether a TCP listen on the port fails, indicating some
// other process already holds it.
func portInUse(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}
