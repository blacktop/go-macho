//===--- swift-serialize-diagnostics.cpp ----------------------------------===//
//
// This source file is part of the Swift.org open source project
//
// Copyright (c) 2014 - 2020 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//
//===----------------------------------------------------------------------===//
//
// Convert localization YAML files to a serialized format.
//
//===----------------------------------------------------------------------===//

#include "swift/Basic/LLVMInitialize.h"
#include "swift/Basic/STLExtras.h"
#include "swift/Localization/LocalizationFormat.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Bitstream/BitstreamReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/EndianStream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/OnDiskHashTable.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>

using namespace swift;
using namespace swift::diag;

namespace options {

static llvm::cl::OptionCategory Category("swift-serialize-diagnostics Options");

static llvm::cl::opt<std::string>
    InputFilePath("input-file-path",
                  llvm::cl::desc("Path to the `.strings` input file"),
                  llvm::cl::cat(Category));

static llvm::cl::opt<std::string>
    OutputDirectory("output-directory",
                    llvm::cl::desc("Directory for the output file"),
                    llvm::cl::cat(Category));

} // namespace options

int main(int argc, char *argv[]) {
  PROGRAM_START(argc, argv);

  llvm::cl::HideUnrelatedOptions(options::Category);
  llvm::cl::ParseCommandLineOptions(argc, argv,
                                    "Swift Serialize Diagnostics Tool\n");

  if (!llvm::sys::fs::exists(options::InputFilePath)) {
    llvm::errs() << "diagnostics file not found\n";
    return EXIT_FAILURE;
  }

  auto localeCode = llvm::sys::path::filename(options::InputFilePath);
  llvm::SmallString<128> SerializedFilePath(options::OutputDirectory);
  llvm::sys::path::append(SerializedFilePath, localeCode);
  llvm::sys::path::replace_extension(SerializedFilePath, ".db");

  SerializedLocalizationWriter Serializer;

  {
    assert(llvm::sys::path::extension(options::InputFilePath) == ".strings");

    StringsLocalizationProducer strings(options::InputFilePath);

    strings.forEachAvailable(
        [&Serializer](swift::DiagID id, llvm::StringRef translation) {
          Serializer.insert(id, translation);
        });
  }

  if (Serializer.emit(SerializedFilePath.str())) {
    llvm::errs() << "Cannot serialize diagnostic file "
                 << options::InputFilePath << '\n';
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
