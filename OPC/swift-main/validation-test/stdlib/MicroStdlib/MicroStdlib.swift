// RUN: %empty-directory(%t)
// RUN: %target-build-swift  -c -whole-module-optimization -parse-as-library -parse-stdlib -Xllvm -basic-dynamic-replacement -module-name Swift -emit-module -runtime-compatibility-version none -emit-module-path %t/Swift.swiftmodule -o %t/Swift.o %S/Inputs/Swift.swift
// RUN: ls %t/Swift.swiftmodule
// RUN: ls %t/Swift.swiftdoc
// RUN: ls %t/Swift.o
// RUN: %target-clang -x c -c %S/Inputs/RuntimeStubs.c -o %t/RuntimeStubs.o
// RUN: %target-build-swift -I %t -runtime-compatibility-version none -module-name main -o %t/hello %S/Inputs/main.swift %t/Swift.o %t/RuntimeStubs.o
// RUN: %target-codesign %t/hello
// RUN: %target-run %t/hello | %FileCheck %s
// REQUIRES: executable_test
// CHECK: Hello

