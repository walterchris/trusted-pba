# Go coding standards

Idiomatic, clean Go for Trusted PBA. These complement the secure-coding guidelines
(compliance baseline §12) and are enforced in review (the **go-reviewer** agent)
and CI (`gofmt` + `go vet` + `golangci-lint`). Project targets **Go 1.26** on
TamaGo.

Grounded in [Effective Go](https://go.dev/doc/effective_go), [Go Code Review
Comments](https://go.dev/wiki/CodeReviewComments), the [Uber Go Style
Guide](https://github.com/uber-go/guide/blob/master/style.md), and modern-Go
guidance ([JetBrains](https://github.com/JetBrains/go-modern-guidelines)).

## 0. The lesson behind this doc
The PR #26 review caught a bespoke `emit()` helper writing to two sinks where the
standard library already provides `io.MultiWriter`. **Before writing a helper, look
for the stdlib type/composition that already does it** (`io.Writer`/`io.Reader`,
`io.MultiWriter`, `io.TeeReader`, `bytes.Buffer`, `errors.Join`, `slices`/`maps`,
`cmp.Or`, …). Reusing the standard interfaces keeps code composable and small.

## 1. Tooling gates (non-negotiable)
- `gofmt` (or `goimports`) — code must be formatted; CI fails otherwise.
- `go vet ./...` — must pass.
- `golangci-lint run` — must pass (config: [`.golangci.yml`](../../.golangci.yml)).
- Run them via `task fmt`, `task vet`, `task lint` (and `task check`).

## 2. Formatting & naming
- `MixedCaps`/`mixedCaps`, never underscores. Exported = capital; keep unexported
  unless a caller needs it.
- No stutter: `opal.Session`, not `opal.OpalSession`. Initialisms keep case:
  `comID`, `parseURL`, `UEFIStatus`.
- Short, consistent receiver names (`s *Session`, not `this`/`self`).
- Keep the happy path left-aligned: return early on errors, no deep nesting.

## 3. Error handling
- Check every error. Never use `_ =` on an error without a comment justifying why
  it is unactionable.
- Wrap with context: `fmt.Errorf("unlock range %d: %w", id, err)`; compare with
  `errors.Is`, extract with `errors.As`, combine with `errors.Join`.
- Define sentinel errors (`var ErrLocked = errors.New("...")`) for conditions
  callers branch on.
- **Never `panic` on attacker- or device-controlled input** (Opal responses,
  policy, device paths). Return an error and fail closed.
- Don't both log and return an error — do one. Errors propagate; the top of the
  call stack decides how to report.

## 4. Interfaces & composition
- Interfaces are small (1–3 methods). Define them where they are **consumed**, not
  where implemented.
- **Accept interfaces, return concrete types.** e.g. the Opal layer takes a
  `transport.TCG` interface; constructors return `*opal.Session`.
- Prefer composing standard interfaces (`io.Writer`, `io.Reader`) over inventing
  parallel ones — this is what makes `io.MultiWriter` etc. usable (see §0).
- `any`, not `interface{}`.

## 5. Simplicity & clean code
- Least code that solves the problem; no speculative abstraction or config (echoes
  CLAUDE.md rule 2). One responsibility per function; extract when a function
  stops fitting on a screen.
- No global mutable state unless required by the runtime; document it when it is.
- Reuse before rewrite: stdlib → existing internal package → new code.

## 6. Concurrency (when it arrives)
- Share memory by communicating; protect shared state with `sync` primitives.
- `context.Context` is the first parameter (`ctx context.Context`), never stored
  in a struct. Honour cancellation.
- Own every goroutine's lifecycle; no leaks. `sync.WaitGroup.Go` (1.25+) to spawn.

## 7. Modern Go (1.26)
- `min`/`max` builtins; `slices`/`maps` packages; `cmp.Or` for first-non-zero.
- `for i := range n` for counted loops; `errors.Join` for multi-error.
- `t.Context()` in tests; `omitzero` JSON tag over `omitempty` for zero values.

## 8. Documentation
- Every exported symbol has a doc comment starting with its name. Each package has
  a package comment (`// Package opal …`).
- Comments explain *why*, not *what*; document `unsafe` usage and pointer
  ownership/lifetime (critical at the UEFI boundary).

## 9. Testing
- Table-driven tests; cover success **and** failure paths. Name subtests.
- `t.Parallel()` where independent; `t.Context()` for contexts.
- Fuzz every parser (Opal responses, policy, device paths) — see baseline §12.
- Never weaken a test to make CI pass (AGENTS.md).

## 10. TamaGo / UEFI specifics
- Check and map **every** UEFI status / transport error to an internal error;
  never ignore (AGENTS.md).
- Wrap all `unsafe` with a justification comment; document pointer ownership and
  lifetime across the firmware boundary.
- Zero sensitive buffers where feasible; never `fmt`/log secrets or raw unlock
  material.
- TamaGo-only files carry `//go:build tamago && amd64`; provide a `//go:build
  !tamago` host stub so `go test ./...`, vet, and linters work off-target.
