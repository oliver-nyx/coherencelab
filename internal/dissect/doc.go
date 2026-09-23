// Package dissect implements first-principles protocol dissection for
// browser-identity reverse engineering labs.
//
// Design goals for expert readers:
//   - Parse TLS ClientHello and HTTP/2 frames from raw bytes (no black-box
//     fingerprint library as the source of truth).
//   - Treat GREASE, extension order, and record-vs-legacy version splits as
//     first-class signals — these are what modern detectors actually use.
//   - Emit annotated findings that teach *why* a field matters, not only
//     whether it "matches a profile".
package dissect
