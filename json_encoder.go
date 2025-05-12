package libddwaf

import (
	"github.com/DataDog/go-libddwaf/v4/internal/bindings"
	"github.com/DataDog/go-libddwaf/v4/internal/pin"
	"github.com/DataDog/go-libddwaf/v4/timer"
)

type jsonEncoder struct {
	// pinner is used to pin the data referenced by the encoded wafObjects.
	pinner pin.Pinner

	// timer makes sure the encoder doesn't spend too much time doing its job.
	timer timer.Timer

	// For each TruncationReason, holds the size that is required to avoid truncation for each truncation that happened.
	truncations map[TruncationReason][]int

	containerMaxSize int
	stringMaxSize    int
	objectMaxDepth   int

	initiallyTruncated bool
}

func newJSONEncoder(pinner pin.Pinner, timer timer.Timer, initiallyTruncated bool) *jsonEncoder {
	return &jsonEncoder{
		pinner:             pinner,
		timer:              timer,
		truncations:        make(map[TruncationReason][]int),
		containerMaxSize:   bindings.MaxContainerSize,
		stringMaxSize:      bindings.MaxStringLength,
		objectMaxDepth:     bindings.MaxContainerDepth,
		initiallyTruncated: initiallyTruncated,
	}
}

// Encode takes a JSON string (as bytes) and returns a wafObject pointer and an error.
// The returned wafObject is the root of the tree of nested wafObjects representing the JSON values.
func (e *jsonEncoder) Encode(jsonBytes []byte) (*bindings.WAFObject, error) {
	// Note: If an overall size limit for jsonBytes is needed, it should be checked here
	// before calling e.parse(). For example, similar to DefaultMaxBytes in the original parser.

	// Reset truncations for this encoding pass, in case the encoder instance is reused.
	e.truncations = make(map[TruncationReason][]int)

	return e.parse(jsonBytes) // Call the parse method from json_parser.go
}

// Truncations returns all truncations that happened since the last call to `Truncations()`,
// or since the beginning of the last Encode call. This map is reset at the start of each Encode call.
func (e *jsonEncoder) Truncations() map[TruncationReason][]int {
	// Return a copy to prevent external modification if the map is to be cleared here.
	// However, standard practice is often to return the map and then clear it if it's a one-time retrieval.
	// The current implementation in encoder.go clears it upon retrieval.
	// Let's stick to that pattern for consistency.
	result := e.truncations
	e.truncations = make(map[TruncationReason][]int) // Reset after retrieval or rely on Encode to reset.
	// For now, Encode resets it, so this just returns the current state.
	return result
}

// addTruncation records a truncation event.
func (e *jsonEncoder) addTruncation(reason TruncationReason, size int) {
	if e.truncations == nil {
		// This should not happen if Encode correctly initializes it.
		e.truncations = make(map[TruncationReason][]int, 3)
	}
	e.truncations[reason] = append(e.truncations[reason], size)
}
