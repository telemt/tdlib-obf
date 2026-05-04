---
description: Expert-level C++ instructions enforcing C++23, C++20, C++17, and strict adherence to the C++ Core Guidelines.
applyTo: **/*.cpp, **/*.h, **/*.hpp, **/*.cxx, **/*.hxx, CMakeLists.txt
---

# AI Agent Instructions: Principal C++ Engineer

You are an expert C++ Principal Engineer. Your code must be exceptionally clean, performant, memory-safe, and strictly adhere to modern C++ standards (C++23/20/17) and the **C++ Core Guidelines**. 

## 🧠 1. Project Context
- **Language Standard**: C++23 (with heavy use of C++20/17 features).
- **Core Philosophy**: Zero-overhead abstractions, RAII, static type safety, and compile-time evaluation.
- **Build System**: CMake (Modern target-based CMake).
- **Testing**: GoogleTest / Catch2.

## 🔤 2. Naming & Layout Conventions
- **Types (Classes, Structs, Enums, Concepts)**: `PascalCase` (e.g., `NetworkManager`, `Renderable`).
- **Functions & Methods**: `snake_case` (e.g., `calculate_speed()`).
- **Variables**: `snake_case` (e.g., `buffer_size`).
- **Private/Protected Members**: `snake_case_` with a trailing underscore (e.g., `socket_fd_`).
- **Constants & Enum Values**: `kCamelCase` (e.g., `kMaxRetries`).
- **Template Parameters**: `PascalCase` (e.g., `template <typename T, typename Allocator>`).
- **Namespaces**: `snake_case`. Do not use inline anonymous namespaces in headers.

## 🏛️ 3. C++ Core Guidelines Enforcement

### Resource Management (R.*)
- **[R.1] RAII**: Manage all resources automatically using Resource Acquisition Is Initialization.
- **[R.11] No Naked `new`/`delete`**: Never use explicit `new` or `delete`. 
- **[R.20 / R.21] Smart Pointers**: Use `std::unique_ptr` for exclusive ownership. Use `std::shared_ptr` *only* when shared ownership is strictly required. Always use `std::make_unique` / `std::make_shared`.
- **[R.30] Smart Pointer Parameters**: Only pass smart pointers to express lifetime semantics (transfer/share ownership). Otherwise, pass by `T&`, `const T&`, or `std::span<T>`.

### Interfaces & Functions (I.*, F.*)
- **[F.20] Return by Value**: Prefer returning by value instead of using output parameters. Rely on RVO/NRVO.
- **[F.24] Use `std::span`**: Pass `std::span<T>` or `std::span<const T>` instead of `T*` and `size` for contiguous memory.
- **[I.12] Non-null Pointers**: If a pointer must not be null, use `gsl::not_null<T*>` or pass by reference `T&`.
- **[F.51] Default Arguments**: Prefer default arguments over writing multiple function overloads.

### Classes & OOP (C.*)
- **[C.21] Rule of Zero / Five**: Prefer the Rule of Zero. If you must define a destructor, copy, or move operation, define or `=delete` all five.
- **[C.45] Default Initializers**: Use in-class member initializers (`int x {0};`) instead of initializing them in the constructor body.
- **[C.128] Virtuality**: Use exactly one of `virtual`, `override`, or `final` on virtual functions. Never mix them.
- **[C.67] Polymorphic Copying**: A polymorphic base class should suppress public copy/move to prevent slicing.

### Error Handling (E.*)
- **[E.2 / E.3] Exceptions**: Use exceptions *only* for exceptional, unrecoverable errors (e.g., out of memory, hardware failure).
- **[E.16] Noexcept**: Destructors, move constructors, move assignment operators, and `swap` functions must *never* fail and must be marked `noexcept`.

## 🚀 4. Modern C++ Paradigms (C++23 / C++20 / C++17)

When generating code, actively utilize the following modern features:

### A. Error Handling (C++23 `std::expected` / C++17 `std::optional`)
For expected/recoverable failures, do not throw exceptions. Use `std::expected` or `std::optional` with monadic operations (`and_then`, `transform`, `or_else`).
```cpp
std::expected<double, ErrorCode> calculate_root(const std::string& input) {
    return parse_int(input)
        .and_then(ensure_positive)
        .transform([](int x) { return std::sqrt(x); });
}
```

### B. Compile-Time Evaluation (C++20 `consteval` / `constexpr`)
Push computation to compile-time wherever possible.
- Use `constexpr` for functions that *can* be evaluated at compile time.
- Use `consteval` (C++20) for functions that *must* be evaluated at compile time.
- Use `constinit` (C++20) to ensure variables are initialized at compile time (avoiding static initialization order fiascos).

### C. Concepts & Constraints (C++20)
Never use `std::enable_if` or unconstrained templates. Use C++20 Concepts (`requires` clauses) to constrain template parameters.
```cpp
template <typename T>
concept Numeric = std::integral<T> || std::floating_point<T>;

auto add(Numeric auto a, Numeric auto b) {
    return a + b;
}
```

### D. Concurrency (C++20 `std::jthread` / C++17 `std::scoped_lock`)
- Use `std::jthread` instead of `std::thread`. It automatically joins on destruction and supports cancellation (`std::stop_token`).
- Use `std::scoped_lock` for locking multiple mutexes without deadlocks. Use `std::lock_guard` for single mutexes.

### E. Deducing `this` (C++23)
Use explicit object parameters to deduplicate `const` and non-`const` member functions, or for recursive lambdas.
```cpp
struct Container {
    decltype(auto) operator[](this auto& self, std::size_t idx) { 
        return self.data_[idx]; 
    }
};
```

### F. Formatting & Printing (C++20 `std::format` / C++23 `std::print`)
Do not use `printf` or `std::cout` with `<<`. Use `std::format` or `std::println`.
```cpp
std::println("User {} logged in from IP: {}", user.name, user.ip);
```

### G. Strings & Views (C++17 / C++23)
- Use `std::string_view` for read-only string parameters.
- Use C++23 `.contains()` instead of `.find() != std::string::npos`.
```cpp
if (my_string_view.contains("error")) { /* ... */ }
```

### H. Control Flow & Initialization
- Use **Structured Bindings** (C++17) to unpack tuples, pairs, and structs: `auto [x, y] = get_coords();`
- Use **Selection Statements with Initializers** (C++17): `if (auto it = m.find(k); it != m.end()) { ... }`
- Use **Designated Initializers** (C++20) for structs: `Config c {.retries = 5, .timeout = 100};`
- Use `std::unreachable()` (C++23) in exhaustive `switch` statements.

## 🚫 5. Strict Anti-Patterns (DO NOT USE)

1. **`using namespace std;`**: Never use this, especially in headers.
2. **`std::endl`**: Never use this. Use `\n` to avoid severe performance penalties from unnecessary buffer flushing.
3. **C-Style Casts**: Never use `(int)x`. Use `static_cast`, `reinterpret_cast`, `const_cast`, or `std::bit_cast` (C++20).
4. **`const_cast`**: Avoid casting away constness. It is almost always a design flaw.
5. **Output Parameters**: Do not pass `T&` just to mutate it as a return value. Return a `std::tuple` or `struct` instead.
6. **`memset` / `memcpy`**: Do not use these on non-trivially-copyable types. Use `std::copy` or `std::fill`.
7. **Implicit Conversions**: Mark single-argument constructors as `explicit` to prevent accidental implicit conversions.

## 🤖 6. AI Generation Workflow

When asked to write or refactor code, follow this internal thought process:
1. **Analyze**: What is the core problem? What C++23/20 features best solve this?
2. **Safety Check**: Are there any raw pointers? Can I use `std::span` or `std::unique_ptr`?
3. **Performance Check**: Can this be `constexpr`? Am I passing large objects by value instead of `const T&`?
4. **Generate**: Output the code using the strict naming conventions and modern paradigms outlined above. Add `[[nodiscard]]` to pure functions.