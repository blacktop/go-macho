//===--- TransformRangeTest.cpp -------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2019 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#include "swift/Basic/STLExtras.h"
#include "llvm/ADT/ArrayRef.h"
#include "gtest/gtest.h"

using namespace swift;

TEST(TransformRangeTest, Empty) {
  auto transform = [](int i) -> float { return float(i); };
  std::function<float (int)> f(transform);
  std::vector<int> v1;
  auto EmptyArray = makeTransformRange(llvm::ArrayRef<int>(v1), f);
  EXPECT_EQ(EmptyArray.empty(), v1.empty());
}

TEST(TransformRangeTest, Subscript) {
  auto transform = [](int i) -> float { return float(i); };
  std::function<float (int)> f(transform);
  std::vector<int> v1;

  v1.push_back(0);
  v1.push_back(2);
  v1.push_back(3);
  v1.push_back(100);
  v1.push_back(-5);
  v1.push_back(-30);

  auto Array = makeTransformRange(llvm::ArrayRef<int>(v1), f);

  EXPECT_EQ(Array.size(), v1.size());
  for (unsigned i = 0, e = Array.size(); i != e; ++i) {
    EXPECT_EQ(Array[i], transform(v1[i]));
  }
}

TEST(TransformRangeTest, Iteration) {
  auto transform = [](int i) -> float { return float(i); };
  std::function<float (int)> f(transform);
  std::vector<int> v1;

  v1.push_back(0);
  v1.push_back(2);
  v1.push_back(3);
  v1.push_back(100);
  v1.push_back(-5);
  v1.push_back(-30);

  auto Array = makeTransformRange(llvm::ArrayRef<int>(v1), f);

  auto VBegin = v1.begin();
  auto VIter = v1.begin();
  auto VEnd = v1.end();
  auto TBegin = Array.begin();
  auto TIter = Array.begin();
  auto TEnd = Array.end();

  // Forwards.
  while (VIter != VEnd) {
    EXPECT_NE(TIter, TEnd);
    EXPECT_EQ(transform(*VIter), *TIter);
    ++VIter;
    ++TIter;
  }

  // Backwards.
  while (VIter != VBegin) {
    EXPECT_NE(TIter, TBegin);

    --VIter;
    --TIter;

    EXPECT_EQ(transform(*VIter), *TIter);
  }
}

TEST(TransformRangeTest, IterationWithSizelessSubscriptlessRange) {
  auto transform = [](int i) -> float { return float(i); };
  std::function<float (int)> f(transform);
  std::vector<int> v1;

  v1.push_back(0);
  v1.push_back(2);
  v1.push_back(3);
  v1.push_back(100);
  v1.push_back(-5);
  v1.push_back(-30);

  auto Array = makeTransformRange(llvm::make_range(v1.begin(), v1.end()), f);

  auto VBegin = v1.begin();
  auto VIter = v1.begin();
  auto VEnd = v1.end();
  auto TBegin = Array.begin();
  auto TIter = Array.begin();
  auto TEnd = Array.end();

  // Forwards.
  while (VIter != VEnd) {
    EXPECT_NE(TIter, TEnd);
    EXPECT_EQ(transform(*VIter), *TIter);
    ++VIter;
    ++TIter;
  }

  // Backwards.
  while (VIter != VBegin) {
    EXPECT_NE(TIter, TBegin);

    --VIter;
    --TIter;

    EXPECT_EQ(transform(*VIter), *TIter);
  }
}
