// Package nego implements cryptographic negotiation
// and secret entrypoint finding.
package nego

/* TODO:
-	add SetSizeLimit() method to allow clients to enforce a limit
	on the produced header size (at the risk of layout failure).
-	incrementally expand allocation mask instead of starting at worst-case
*/

import (
	"fmt"
	"sort"
	"errors"
	"crypto/cipher"
	"encoding/binary"
	"dissent/crypto"
)


type Entry struct {
	Suite crypto.Suite	// Ciphersuite this public key is drawn from
	PubKey crypto.Point	// Public key of this entrypoint's owner
	Data []byte		// Entrypoint data decryptable by owner
}


// Writer produces a cryptographic negotiation header,
// which conceals a variable number of "entrypoints"
// within a variable-length binary blob of random-looking bits.
// Each entrypoint hidden in the blob is discoverable and usable only
// by the owner of a particular public key.
// Different public keys may be drawn from different ciphersuites,
// in any combination, without coordination between the ciphersuites.
//
// Each entrypoint contains a short fixed-length blob of encrypted data,
// which the owner of the entrypoint can decrypt and use
// to obtain keys and pointers to the "real" content.
// This "real" content is typically located after the negotiation header
// and encrypted with a symmetric key included in the entrypoint data,
// which can be (but doesn't have to be) shared by many or all entrypoints.
//
type Writer struct {
	layout skipLayout
	maxLen int		// Client-specified maximum header length
}


// A ciphersuite used in a negotiation header.
type suiteKey struct {

	// Ephemeral Diffie-Hellman key for all key-holders using this suite.
	// Should have a uniform representation, e.g., an Elligator point.
	dhpri crypto.Secret
	dhpub crypto.Point
	dhrep []byte
}

/*
func (s *suiteKey) fresh(suite crypto.Suite) {
	dhpri := entry.suite.Secret().Pick(rand)
	dhpub := entry.Suite.Point().Mul(nil, dhpri)
	dhrep := dhpub.UniformEncode()
	suites[suite] = suite{dhpri,dhpub}
}
*/

type suiteInfo struct {
	ste crypto.Suite		// ciphersuite
	tag []uint32			// per-position pseudorandom tag
	pos []int			// alternative point positions
	plen int			// length of each point in bytes
	max int				// limit of highest point field

	// layout info
	//nodes []*node			// layout node for reserved positions
	lev int				// layout-chosen level for this suite
}

func (si *suiteInfo) String() string {
	return "Suite "+si.ste.String()
}

// Determine all the alternative DH point positions for a ciphersuite.
func (si *suiteInfo) init(ste crypto.Suite, nlevels int) {
	si.ste = ste
	si.tag = make([]uint32, nlevels)
	si.pos = make([]int, nlevels)
	si.plen = ste.Point().(crypto.Hiding).HideLen()	// XXX

	// Create a pseudo-random stream from which to pick positions
	str := fmt.Sprintf("NegoCipherSuite:%s", ste.String())
	rand := crypto.HashStream(ste, []byte(str), nil)

	// Alternative 0 is always at position 0, so start with level 1.
	levofs := 0			// starting offset for current level
	fmt.Printf("Suite %s positions:\n", ste.String())
	for i := 0; i < nlevels; i++ {

		// Pick a random position within this level
		var buf [4]byte
		rand.XORKeyStream(buf[:],buf[:])
		levlen := 1 << uint(i)	// # alt positions at this level
		levmask := levlen - 1	// alternative index mask
		si.tag[i] = binary.BigEndian.Uint32(buf[:])
		levidx := int(si.tag[i]) & levmask
		si.pos[i] = levofs + levidx * si.plen

		fmt.Printf("%d: idx %d/%d pos %d\n",
				i, levidx, levlen, si.pos[i])

		levofs += levlen * si.plen	// next level table offset
	}

	// Limit of highest point field
	si.max = si.pos[nlevels-1] + si.plen
}

// Try to reserve a space for level i of this ciphersuite in the layout.
// If we can't due to a conflict, mark the existing node as conflicted,
// so its owner subsequently knows that it can't use that position either.
/*
func (si *suiteInfo) layout(w *Writer, i int) bool {
	var n node
	lo := si.pos[i]			// compute byte extent
	hi := lo + si.plen
	n.init(si, lo, hi, si.tag[i])	// create suitable node
	fmt.Printf("try insert %s:%d at %d-%d\n", si.ste.String(), i, lo, hi)
	return w.layout.reserve(si, lo, hi, si.tag[i])
}
*/

 


// A sortable list of suiteInfo objects.
type suites struct {
	s []suiteInfo
}

func (s *suites) Len() int {
	return len(s.s)
}
func (s *suites) Less(i,j int) bool {
	return s.s[i].max < s.s[j].max
}
func (s *suites) Swap(i,j int) {
	s.s[i],s.s[j] = s.s[j],s.s[i]
}


// Set the optional maximum length for the negotiation header,
// affecting subsequent calls to Layout()
func (w *Writer) SetMaxLen(max int) {
	w.maxLen = max
}

// Initialize a Writer to produce one or more negotiation header
// containing a specified set of entrypoints,
// whose owners' public keys are drawn from a given set of ciphersuites.
//
// The caller must provide a map 'suiteLevel' with one key per ciphersuite,
// whose value is the maximum "level" in the header 
// at which the ciphersuite's ephemeral Diffie-Hellman Point may be encoded.
// This maximum level must be standardized for each ciphersuite,
// and should be log2(maxsuites), where maxsuites is the maximum number
// of unique ciphersuites that are likely to exist when this suite is defined.
//
// All entrypoints will carry a payload entryLen bytes long,
// although the content of these payloads need not be specified yet.
// This function lays out the entrypoints in the negotiation header,
// and returns the total size of the negotiation headers
// that will be produced from this layout.
//
// After this initialization and layout computation,
// multiple independent negotiation headers with varying entrypoint data
// may be produced more efficiently via Write().
//
func (w *Writer) Layout(suiteLevel map[crypto.Suite]int,
			entryLen int, entrypoints []Entry,
			rand cipher.Stream) (int,error) {

	// Determine the set of ciphersuites in use.
/*
	suites := make(map[crypto.Suite]struct{})
	for i := range(entrypoints) {
		entry := entrypoints[i]
		if _,ok := suites[suite]; !ok {
			// First time we've seen this ciphersuite.
			suites[suite] = struct{}{}
		}
	}
*/

	// Compute the alternative DH point positions for each ciphersuite,
	// and the maximum byte offset for each.
	stes := suites{}
	stes.s = make([]suiteInfo, 0, len(suiteLevel))
	max := 0
	for suite,nlevels := range suiteLevel {
		si := suiteInfo{}
		si.init(suite,nlevels)
		if si.max > max {
			max = si.max
		}
		stes.s = append(stes.s, si)
	}
	nsuites := len(stes.s)
	if nsuites > 255 {
		// Our reservation calculation scheme currently can't handle
		// more than 255 ciphersuites.
		return 0,errors.New("too many ciphersuites")
	}
	if w.maxLen != 0 && max > w.maxLen {
		max = w.maxLen
	}

	// Sort the ciphersuites in order of max position,
	// to give ciphersuites with most restrictive positioning
	// "first dibs" on the lowest positions.
	sort.Sort(&stes)

	// Create two reservation layouts:
	// - In w.layout only each ciphersuite's primary position is reserved.
	// - In exclude we reserve _all_ positions in each ciphersuite.
	// Since the ciphersuites' points will be computed in this same order,
	// each successive ciphersuite's primary position must not overlap
	// any point position for any ciphersuite previously computed,
	// but can overlap positions for ciphersuites to be computed later.
	w.layout.reset()
	var exclude skipLayout
	exclude.reset()
	hdrlen := 0
	for i := 0; i < nsuites; i++ {
		si := &stes.s[i]
		//fmt.Printf("max %d: %s\n", si.max, si.ste.String())

		// Reserve all our possible positions in exclude layout,
		// picking the first non-conflicting position as our primary.
		lev := len(si.pos)
		for j := lev-1; j >= 0; j-- {
			lo := si.pos[j]
			hi := lo + si.plen
			//fmt.Printf("reserving [%d-%d]\n", lo,hi)
			if exclude.reserve(lo,hi,false,si) && j == lev-1 {
				lev = j		// no conflict, shift down
			}
		}
		if lev == len(si.pos) {
			return 0,errors.New("no viable position for suite"+
						si.ste.String())
		}
		si.lev = lev	// lowest unconflicted, non-shadowed level

		// Permanently reserve the primary point position in w.layout
		lo := si.pos[lev]
		hi := lo + si.plen
		if hi > hdrlen {
			hdrlen = hi
		}
		//fmt.Printf("picked level %d at [%d-%d]\n", lev, lo,hi)
		if !w.layout.reserve(lo,hi,true,si) {
			panic("thought we had that position reserved??")
		}
	}

	fmt.Printf("Total hdrlen: %d\n", hdrlen)
	fmt.Printf("Point layout:\n")
	w.layout.dump()

	return hdrlen,nil
}


// 
//func (w *Writer) Write(entryData map[Entry][]byte, suffix []byte)
