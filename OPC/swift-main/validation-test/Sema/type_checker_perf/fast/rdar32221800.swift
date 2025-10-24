// RUN: %target-typecheck-verify-swift -solver-expression-time-threshold=1
// REQUIRES: tools-release,no_asan

func test(header_field_mark: Bool?, header_value_mark: Bool?,
  url_mark: Bool?, body_mark: Bool?, status_mark: Bool?) {
  assert(((header_field_mark != nil ? 1 : 0) +
      (header_value_mark != nil ? 1 : 0) +
      (url_mark != nil ? 1 : 0)  +
      (body_mark != nil ? 1 : 0) +
      (status_mark != nil ? 1 : 0)) <= 1)
}
