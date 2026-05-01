// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package libddwaf

type Encoder struct {
	Config      EncoderConfig
	Truncations Truncations
}

func (e *Encoder) WriteString(obj *WAFObject, str string) {
	if len(str) > e.Config.maxStringSize() {
		e.Truncations.Record(StringTooLong, len(str))
		str = str[:e.Config.maxStringSize()]
	}
	obj.SetString(e.Config.Pinner, str)
}

func (e *Encoder) WriteLiteralString(obj *WAFObject, str string) {
	if len(str) > e.Config.maxStringSize() {
		e.Truncations.Record(StringTooLong, len(str))
		str = str[:e.Config.maxStringSize()]
	}
	obj.SetLiteralString(e.Config.Pinner, str)
}

func (e *Encoder) Timeout() bool {
	return e.Config.Timer != nil && e.Config.Timer.Exhausted()
}
