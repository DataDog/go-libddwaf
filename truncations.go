package libddwaf

type Truncations struct {
	StringTooLong     []int
	ContainerTooLarge []int
	ObjectTooDeep     []int
}

func (t *Truncations) Record(reason TruncationReason, size int) {
	switch reason {
	case StringTooLong:
		t.StringTooLong = append(t.StringTooLong, size)
	case ContainerTooLarge:
		t.ContainerTooLarge = append(t.ContainerTooLarge, size)
	case ObjectTooDeep:
		t.ObjectTooDeep = append(t.ObjectTooDeep, size)
	}
}

func (t *Truncations) Merge(other Truncations) {
	t.StringTooLong = append(t.StringTooLong, other.StringTooLong...)
	t.ContainerTooLarge = append(t.ContainerTooLarge, other.ContainerTooLarge...)
	t.ObjectTooDeep = append(t.ObjectTooDeep, other.ObjectTooDeep...)
}

func (t Truncations) IsEmpty() bool {
	return len(t.StringTooLong) == 0 && len(t.ContainerTooLarge) == 0 && len(t.ObjectTooDeep) == 0
}

func (t Truncations) AsMap() map[TruncationReason][]int {
	if t.IsEmpty() {
		return nil
	}
	m := make(map[TruncationReason][]int, 3)
	if len(t.StringTooLong) > 0 {
		m[StringTooLong] = t.StringTooLong
	}
	if len(t.ContainerTooLarge) > 0 {
		m[ContainerTooLarge] = t.ContainerTooLarge
	}
	if len(t.ObjectTooDeep) > 0 {
		m[ObjectTooDeep] = t.ObjectTooDeep
	}
	return m
}
