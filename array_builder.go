// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

// ArrayBuilder accumulates WAFObject entries and commits them to a parent
// WAFObject on Close. It is not safe for concurrent use.
type ArrayBuilder struct {
	enc     *Encoder
	parent  *WAFObject
	entries []WAFObject
	skipped int
	closed  bool
}

// Array returns a new ArrayBuilder that will commit its entries into parent.
// An optional capacityHint pre-allocates the backing slice (capped at MaxContainerSize).
func (e *Encoder) Array(parent *WAFObject, capacityHint ...int) *ArrayBuilder {
	var initial int
	if len(capacityHint) > 0 && capacityHint[0] > 0 {
		initial = capacityHint[0]
		if cap := e.Config.maxContainerSize(); initial > cap {
			initial = cap
		}
	}
	return &ArrayBuilder{enc: e, parent: parent, entries: make([]WAFObject, 0, initial)}
}

// NextValue appends a new slot to the array and returns a pointer to the
// WAFObject for the caller to populate. Returns nil when the builder is at
// MaxContainerSize capacity. The caller must populate the slot or call DropLast
// before calling NextValue again.
func (b *ArrayBuilder) NextValue() *WAFObject {
	if len(b.entries) >= b.enc.Config.maxContainerSize() {
		return nil
	}
	b.entries = append(b.entries, WAFObject{})
	return &b.entries[len(b.entries)-1]
}

// Skip records that an array element was intentionally omitted. The count is
// used by Close to record a ContainerTooLarge truncation if any were skipped.
func (b *ArrayBuilder) Skip() { b.skipped++ }

// DropLast removes the most recently appended entry. No-op if the builder has
// no entries. Use this to undo a NextValue call when encoding the value fails.
func (b *ArrayBuilder) DropLast() {
	if len(b.entries) == 0 {
		return
	}
	b.entries = b.entries[:len(b.entries)-1]
}

// Close commits the accumulated entries to the parent WAFObject. If any entries
// were skipped, a ContainerTooLarge truncation is recorded. Calling Close more
// than once is safe and has no additional effect.
func (b *ArrayBuilder) Close() {
	if b.closed {
		return
	}
	b.closed = true
	if b.skipped > 0 {
		b.enc.Truncations.Record(ContainerTooLarge, len(b.entries)+b.skipped)
	}
	_ = b.parent.SetArrayData(b.enc.Config.Pinner, b.entries)
}
