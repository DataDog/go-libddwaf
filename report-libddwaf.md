# Bug Report: NULL Pointer Dereference in ddwaf_object_from_json

## Summary

`emplace()` in `src/json_utils.cpp` dereferences its `ddwaf_object *object` parameter without a NULL check. `ddwaf_object_stringl()` can return `nullptr` when malloc fails, causing SIGSEGV.

**Impact**: 45 crashes across 10 production hosts (Feb 26, 2026) while parsing the 193KB embedded ruleset.

## Root Cause

```cpp
// src/json_utils.cpp — emplace()
bool emplace(ddwaf_object *object)
{
    bool res = true;
    const bool is_container = (object->type & (DDWAF_OBJ_MAP | DDWAF_OBJ_ARRAY)) != 0;
    // ↑ object dereferenced without NULL check
```

The `String()` handler calls `emplace(ddwaf_object_stringl(&object, str, length))`. When `ddwaf_object_string_helper()` fails to malloc the string copy, it returns `nullptr`, which `emplace()` dereferences.

**Note**: `StartObject()`, `StartArray()`, `Int()`, `Uint()`, etc. are NOT affected — their underlying `ddwaf_object_*` functions do not allocate and always return the (non-NULL) stack pointer.

**Contrast**: `Key()` correctly handles allocation failure with `if (key_ == nullptr) { return false; }`.

## Suggested Fix

```cpp
bool emplace(ddwaf_object *object)
{
    if (object == nullptr) { return false; }  // ADD THIS LINE

    bool res = true;
    const bool is_container = (object->type & (DDWAF_OBJ_MAP | DDWAF_OBJ_ARRAY)) != 0;
    // ... rest unchanged
}
```

## Secondary Issues

1. **RapidJSON allocation safety**: `internal/stack.h` — `Resize()` does not check `allocator_->Realloc()` return. The assert is a no-op in release builds (NDEBUG). Consider overriding RAPIDJSON_ASSERT to throw.

2. **Inverted `[[unlikely]]` hints**: `string_view_stream::Peek()`/`Take()` mark `idx < src.size()` as `[[unlikely]]` — this is the normal path (stream not exhausted), should be `[[likely]]`.

## Versions Affected

- libddwaf v1.30.0 (confirmed), likely v1.29.0+ (bug present since `ddwaf_object_from_json` introduced)
- **Fixed on master (v2.0.0-alpha0)**: The `owned_object` refactoring with `try/catch(...)` in `emplace()` and the custom allocator system eliminates this class of bug. Verified: 0 SIGSEGV with the same failmalloc sweep that produces 27 crashes on v1.30.0.
