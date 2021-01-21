// Package fastrand implements fast pesudorandom number generator
// that should scale well on multi-CPU systems.
//
// Use crypto/rand instead of this package for generating
// cryptographically secure random numbers.
package rand

import (
	"reflect"
	"sync"
	"time"
	"unsafe"
)

const (
	rngMax  = 1 << 63
	rngMask = rngMax - 1
)

var rngPool = sync.Pool{
	New: func() interface{} {
		return new(RNG)
	},
}

// Uint32 returns pseudorandom uint32.
//
// It is safe calling this function from concurrent goroutines.
func Uint32() uint32 {
	r := rngPool.Get().(*RNG)
	defer rngPool.Put(r)
	return r.Uint32()
}

func Uint64() uint64 {
	r := rngPool.Get().(*RNG)
	defer rngPool.Put(r)
	return r.Uint64()
}

func Uint64n(n uint64) uint64 {
	r := rngPool.Get().(*RNG)
	defer rngPool.Put(r)
	return r.Uint64n(n)
}

// Read generates len(p) random bytes from the default Source and
// writes them into p. It always returns len(p) and a nil error.
// Read, unlike the Rand.Read method, is safe for concurrent use.
func Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) <= 4 {
		u32 := Uint32()
		for i := range p {
			p[i] = byte(u32)
			u32 >>= 8
		}
		return len(p), nil
	}
	r := rngPool.Get().(*RNG)
	defer rngPool.Put(r)
	var u32 []uint32
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&p))
	uh := (*reflect.SliceHeader)(unsafe.Pointer(&u32))
	uh.Data = bh.Data
	uh.Len = bh.Len / 4
	uh.Cap = uh.Cap / 4
	r.uint32s(u32)
	if n := uh.Len*4 - bh.Len; n != 0 {
		uh.Data = bh.Data + uintptr(n)
		u32[uh.Len-1] = r.Uint32()
	}
	return len(p), nil
}

// Uint32n returns pseudorandom uint32 in the range [0..maxN).
//
// It is safe calling this function from concurrent goroutines.
func Uint32n(maxN uint32) uint32 {
	x := Uint32()
	// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
	return uint32((uint64(x) * uint64(maxN)) >> 32)
}

func Int31n(n int32) int32 {
	return int32(Uint32n(uint32(n)))
}

func Intn(n int) int {
	if n <= 1<<31-1 {
		return int(Int31n(int32(n)))
	}
	return int(Uint64n(uint64(n)))
}

func Int63() int64 {
	return int64(Uint64() & rngMask)
}

func Int31() int32 {
	return int32(Uint32())
}

// RNG is a pseudorandom number generator.
//
// It is unsafe to call RNG methods from concurrent goroutines.
type RNG struct {
	x uint32
}

// Uint32 returns pseudorandom uint32.
//
// It is unsafe to call this method from concurrent goroutines.
func (r *RNG) Uint32() uint32 {
	for r.x == 0 {
		r.x = func() uint32 {
			x := time.Now().UnixNano()
			return uint32((x >> 32) ^ x)
		}()
	}
	// See https://en.wikipedia.org/wiki/Xorshift
	x := r.x
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 5
	r.x = x
	return x
}

func (r *RNG) Uint64() uint64 {
	return uint64(r.Uint32())<<32 | uint64(r.Uint32())
}

// Uint32n returns pseudorandom uint32 in the range [0..maxN).
//
// It is unsafe to call this method from concurrent goroutines.
func (r *RNG) Uint32n(maxN uint32) uint32 {
	x := r.Uint32()
	// See http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
	return uint32((uint64(x) * uint64(maxN)) >> 32)
}

// Uint64n returns pseudorandom uint32 in the range [0..maxN).
//
// It is unsafe to call this method from concurrent goroutines.
func (r *RNG) Uint64n(maxN uint64) uint64 {
	return uint64(r.Uint32n(uint32(maxN>>32)))<<32 | uint64(Uint32())
}

func (r *RNG) uint32s(u32 []uint32) {
	x := r.x
	for i := range u32 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		u32[i] = x
	}
	r.x = x
}
