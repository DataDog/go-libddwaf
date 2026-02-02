# Migration Guide: v4 → v5

## Breaking Changes

### 1. Context.Run now requires context.Context
**Before:**
```go
result, err := ctx.Run(waf.RunAddressData{Data: data})
```
**After:**
```go
result, err := ctx.Run(context.Background(), waf.RunAddressData{Data: data})
```

### 2. Handle.NewContext now requires context.Context
**Before:**
```go
wafCtx, err := wafHandle.NewContext(opts...)
```
**After:**
```go
wafCtx, err := wafHandle.NewContext(context.Background(), opts...)
```

### 3. Context.SubContext now requires context.Context
**Before:**
```go
subCtx, err := ctx.SubContext()
```
**After:**
```go
subCtx, err := ctx.SubContext(context.Background())
```

### 4. Builder.Build() now returns an error
**Before:**
```go
wafHandle := builder.Build()
```
**After:**
```go
wafHandle, err := builder.Build()
if err != nil {
    // handle error
}
```

### 5. WAFObject and WAFObjectKV are now opaque structs
`WAFObject` and `WAFObjectKV` are no longer type aliases to internal bindings types. They are now opaque structs wrapping the internal types to provide a cleaner public API.

### 6. Encodable interface changes
The `Encodable` interface's `Encode` method no longer takes a `*bindings.WAFObject`. It now takes a `*WAFObject` (the new opaque struct) and an `EncoderConfig`.

**Before:**
```go
Encode(pinner pin.Pinner, obj *bindings.WAFObject, depth int) (map[TruncationReason][]int, error)
```
**After:**
```go
Encode(config EncoderConfig, obj *WAFObject, depth int) (map[TruncationReason][]int, error)
```

### 7. depthOf uses Timer and no longer uses context.Background()
The internal `depthOf` function in the encoder now takes a `timer.Timer` instead of relying on `context.Background()` for timeout checks.
