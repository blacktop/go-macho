// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "CwlDemangle",
    products: [
        .library(name: "CwlDemangle", targets: ["CwlDemangle"]),
        .executable(name: "demangle", targets: ["CwlDemangleTool"]),
    ],
    targets: [
        .target(
            name: "CwlDemangle",
            path: "CwlDemangle",
            sources: ["CwlDemangle.swift"]
        ),
        .target(
            name: "CwlDemangleTool",
            dependencies: ["CwlDemangle"],
            path: "CwlDemangle",
            sources: ["main.swift"],
            resources: [.copy("manglings.txt")]
        ),
        .testTarget(
            name: "CwlDemangleTests",
            dependencies: ["CwlDemangle"],
            path: "CwlDemangleTests"
        ),
    ],
    swiftLanguageVersions: [.v4, .v4_2, .v5]
)
