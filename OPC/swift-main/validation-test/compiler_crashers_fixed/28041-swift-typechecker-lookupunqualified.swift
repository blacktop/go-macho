// This source file is part of the Swift.org open source project
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

// Test is no longer valid as there is no longer `map` as a free function in Swift 3
// DUPLICATE-OF: 26813-generic-enum-tuple-optional-payload.swift
// RUN: not %target-swift-frontend %s -typecheck
let a{{map($0
