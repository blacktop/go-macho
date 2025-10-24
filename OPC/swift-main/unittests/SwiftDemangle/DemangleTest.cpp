//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//

#include <stdlib.h>

#include "swift/SwiftDemangle/SwiftDemangle.h"
#include "gtest/gtest.h"

TEST(FunctionNameDemangleTests, CorrectlyDemangles) {
  char OutputBuffer[128];

  const char *FunctionName = "_TFC3foo3bar3basfT3zimCS_3zim_T_";
  const char *DemangledName = "foo.bar.bas(zim: foo.zim) -> ()";

  size_t Result = swift_demangle_getDemangledName(FunctionName, OutputBuffer,
                                                  sizeof(OutputBuffer));

  EXPECT_STREQ(DemangledName, OutputBuffer);
  EXPECT_EQ(Result, strlen(DemangledName));

  // Make sure the SynthesizeSugarOnTypes option is functioning.
  const char *FunctionNameWithSugar = "_TF4main3fooFT3argGSqGSaSi___T_";
  const char *DemangledNameWithSugar = "main.foo(arg: [Swift.Int]?) -> ()";

  Result = swift_demangle_getDemangledName(FunctionNameWithSugar, OutputBuffer,
                                           sizeof(OutputBuffer));

  EXPECT_STREQ(DemangledNameWithSugar, OutputBuffer);
  EXPECT_EQ(Result, strlen(DemangledNameWithSugar));
}

TEST(FunctionNameDemangleTests, NewManglingPrefix) {
  char OutputBuffer[128];

  const char *FunctionName = "$s1a10run_MatMulyySiF";
  const char *FunctionNameNew = "$s1a10run_MatMulyySiF";
  const char *DemangledName = "a.run_MatMul(Swift.Int) -> ()";
  const char *SimplifiedName = "run_MatMul(_:)";

  size_t Result = swift_demangle_getDemangledName(FunctionName, OutputBuffer,
                                                  sizeof(OutputBuffer));

  EXPECT_STREQ(DemangledName, OutputBuffer);
  EXPECT_EQ(Result, strlen(DemangledName));

  Result = swift_demangle_getDemangledName(FunctionNameNew, OutputBuffer,
                                           sizeof(OutputBuffer));

  EXPECT_STREQ(DemangledName, OutputBuffer);
  EXPECT_EQ(Result, strlen(DemangledName));

  Result = swift_demangle_getSimplifiedDemangledName(FunctionName, OutputBuffer,
                                                     sizeof(OutputBuffer));

  EXPECT_STREQ(SimplifiedName, OutputBuffer);
  EXPECT_EQ(Result, strlen(SimplifiedName));
}

TEST(FunctionNameDemangledTests, WorksWithNULLBuffer) {
  const char *FunctionName = "_TFC3foo3bar3basfT3zimCS_3zim_T_";
  const char *DemangledName = "foo.bar.bas(zim: foo.zim) -> ()";

  // When given a null buffer, swift_demangle_getDemangledName should still be
  // able to return the size of the demangled string.
  size_t Result = swift_demangle_getDemangledName(FunctionName, nullptr, 0);

  EXPECT_EQ(Result, strlen(DemangledName));
}

TEST(FunctionNameDemangleTests, IgnoresNonMangledInputs) {
  const char *FunctionName = "printf";
  char OutputBuffer[] = "0123456789abcdef";

  size_t Result = swift_demangle_getDemangledName(FunctionName, OutputBuffer,
                                                  sizeof(OutputBuffer));

  EXPECT_EQ(0U, Result);
  EXPECT_STREQ("0123456789abcdef", OutputBuffer);
}

TEST(FunctionNameDemangleTests, ModuleName) {
  const char *Sym1 = "_TtCs5Class";
  const char *ModuleName1 = "Swift";
  const char *Sym2 = "_TtCC3Mod7ExampleP33_211017DA67536A354F5F5EB94C7AC12E2Pv";
  const char *ModuleName2 = "Mod";
  char OutputBuffer[128];

  size_t Result = swift_demangle_getModuleName(Sym1, OutputBuffer,
                                               sizeof(OutputBuffer));
  EXPECT_STREQ(ModuleName1, OutputBuffer);
  EXPECT_EQ(Result, strlen(ModuleName1));

  Result = swift_demangle_getModuleName(Sym2, OutputBuffer,
                                        sizeof(OutputBuffer));
  EXPECT_STREQ(ModuleName2, OutputBuffer);
  EXPECT_EQ(Result, strlen(ModuleName2));
}

