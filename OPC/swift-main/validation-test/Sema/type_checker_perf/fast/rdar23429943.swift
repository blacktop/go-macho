// RUN: %target-typecheck-verify-swift -solver-expression-time-threshold=1
// REQUIRES: tools-release,no_asan

let _ = [0].reduce([Int]()) {
  return $0.count == 0 && ($1 == 0 || $1 == 2 || $1 == 3) ? [] : $0 + [$1]
}
