// Frasil's client for Kotlin: the glue UniFFI generates from
// crates/frasil-uniffi (scripts/bindings.sh), loaded through JNA from the
// library Cargo builds in the repository's target/debug.
plugins { kotlin("jvm") version "2.1.20" }
repositories { mavenCentral() }
dependencies {
    implementation("net.java.dev.jna:jna:5.16.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
}
kotlin { jvmToolchain(21) }
tasks.test {
    useJUnitPlatform()
    // The generated code loads this library through JNA, outside Gradle's classpath.
    inputs.file(file("../../target/debug/${System.mapLibraryName("frasil_uniffi")}"))
    systemProperty("jna.library.path", file("../../target/debug").absolutePath)
}
