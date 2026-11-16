// swift-tools-version: 6.0
// Frasil's client for Swift: the glue UniFFI generates from crates/frasil-uniffi
// (scripts/bindings.sh), over the library Cargo builds in the repository's
// target/debug.
import PackageDescription

let package = Package(
    name: "Frasil",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "Frasil", targets: ["Frasil"])],
    targets: [
        .target(name: "FrasilFFI", publicHeadersPath: "include"),
        .target(
            name: "Frasil",
            dependencies: ["FrasilFFI"],
            linkerSettings: [
                .unsafeFlags([
                    "-L", "../../target/debug", "-lfrasil_uniffi",
                    "-Xlinker", "-rpath", "-Xlinker", "../../target/debug",
                ])
            ]
        ),
        .testTarget(name: "FrasilTests", dependencies: ["Frasil"]),
    ]
)
