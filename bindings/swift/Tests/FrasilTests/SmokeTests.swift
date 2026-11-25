import Foundation
import Testing
@testable import Frasil

/// Collects what a listener hears, for a test to wait on.
private final class Heard<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [T] = []

    func add(_ value: T) {
        lock.lock()
        values.append(value)
        lock.unlock()
    }

    func all() -> [T] {
        lock.lock()
        defer { lock.unlock() }
        return values
    }

    /// Waits up to ten seconds until a value passes `check`.
    func until(_ check: (T) -> Bool) async throws -> T {
        for _ in 0..<200 {
            if let found = all().first(where: check) { return found }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        Issue.record("nothing heard in time: \(all())")
        throw CancellationError()
    }
}

private final class Durable: DurableListener, @unchecked Sendable {
    let heard = Heard<Bool>()
    func durable(durable: Bool) { heard.add(durable) }
    func failed(message: String) {}
}

private final class Statuses: BlobStatusListener, @unchecked Sendable {
    let heard = Heard<BlobStatus>()
    func status(status: BlobStatus) { heard.add(status) }
    func failed(message: String) {}
}

private final class Arrived: ArrivalListener, @unchecked Sendable {
    let heard = Heard<Arrival>()
    func arrived(arrival: Arrival) { heard.add(arrival) }
}

private final class Checkpoints: CheckpointListener, @unchecked Sendable {
    let heard = Heard<CheckpointReport>()
    func reported(report: CheckpointReport) { heard.add(report) }
}

@Test func aDeviceHoldsASpaceAndItsBlobs() async throws {
    let device = try await Device.openInMemory(
        unlockKey: Data(repeating: 1, count: 32), options: DeviceOptions(blobCache: 1 << 20))
    let arrived = Arrived()
    let arrivals = await device.arrivals(listener: arrived)
    let space = try await device.createSpace()
    #expect(await device.spaces() == [space.id()])
    _ = try await arrived.heard.until { $0 == .space(space: space.id()) }

    // No peer: the space has something unsent.
    let durable = Durable()
    let following = space.observeDurable(listener: durable)
    #expect(try await durable.heard.until { _ in true } == false)
    #expect(await space.isDurable() == false)

    let blobs = try space.createBlobs()
    let bytes = Data("hello from Swift".utf8)
    let blob = try await blobs.put(name: "hello.txt", bytes: bytes)
    #expect(try await blobs.get(id: blob) == bytes)
    #expect(try await blobs.status(id: blob) == .readable)
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try bytes.write(to: file)
    let fromFile = try await blobs.putFile(name: "file.txt", path: file.path, listener: nil)
    #expect(try await blobs.get(id: fromFile) == bytes)
    try FileManager.default.removeItem(at: file)
    let statuses = Statuses()
    let watching = try blobs.observeStatus(id: blob, listener: statuses)
    #expect(try await statuses.heard.until { _ in true } == .readable)
    let hash = try #require(try await blobs.contentHash(id: blob))
    #expect(hash.count == 32)
    #expect(try await blobs.getRange(id: blob, offset: 6, length: 4) == Data("from".utf8))
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("frasil-get-to-file-\(UUID().uuidString)")
    try await blobs.getToFile(id: blob, path: path.path, listener: nil)
    #expect(try Data(contentsOf: path) == bytes)
    try? FileManager.default.removeItem(at: path)
    _ = try await arrived.heard.until { $0 == .stream(space: space.id(), stream: blobs.id()) }

    // A blob this device put, in a space with no peer: kept, outside the
    // cache's budget, and its change waits for an acknowledgement.
    let local = try await blobs.local(id: blob)
    #expect(local.state == .kept && local.size == UInt64(bytes.count) && local.bytes > local.size)
    let usage = await device.blobCacheUsage()
    #expect(usage.budget == 1 << 20 && usage.cached == 0 && usage.kept >= local.bytes)
    #expect(try await blobs.isDurable(id: blob) == false)
    #expect(try await blobs.pending().sorted() == [blob, fromFile].sorted())
    try await blobs.keep(id: blob, listener: nil)
    #expect(try await blobs.get(id: blob, read: ReadOptions(local: true)) == bytes)

    // A reader over it reads any range, and every check has run on a blob
    // that is whole here.
    let reader = try await blobs.openReader(id: blob)
    #expect(try await reader.fetchSize() == UInt64(bytes.count))
    #expect(try await reader.readAt(offset: 6, length: 4) == Data("from".utf8))
    #expect(try await reader.readAt(offset: 11, length: 100) == Data("Swift".utf8))
    #expect(try await reader.readAt(offset: 100, length: 1).isEmpty)
    #expect(reader.size() == UInt64(bytes.count))
    #expect(reader.readAhead() == 8)
    reader.setReadAhead(chunks: 1000)
    #expect(reader.readAhead() == 64)
    #expect(reader.windowBytes() == 0)
    try await reader.end()

    // Dropped, with nothing connected that could send it again: missing.
    try await blobs.dropLocal(id: blob)
    #expect(try await blobs.local(id: blob) == BlobLocal(state: .absent, bytes: 0, size: local.size))
    #expect(try await blobs.status(id: blob) == .missing)
    #expect(try await blobs.get(id: blob) == nil)

    space.pauseSync()
    #expect(space.isSyncPaused())
    try device.resumeSync(spaces: [space.id()])
    #expect(!space.isSyncPaused())

    for subscription in [arrivals, following, watching] { subscription.cancel() }
    try await device.shutdown()
}

@Test func anAdministratorProposesACheckpointAndFollowsIt() async throws {
    let device = try await Device.openInMemory(unlockKey: Data(repeating: 2, count: 32))
    device.setCheckpointPolicy(policy: CheckpointPolicy(propose: false))
    #expect(
        device.checkpointPolicy()
            == CheckpointPolicy(propose: false, forget: true, rosterEvents: 1024, frameBytes: 4_194_304)
    )
    let reports = Checkpoints()
    let following = device.checkpointReports(listener: reports)
    let space = try await device.createSpace()
    // The space's creator holds the top rank.
    #expect(try await space.myRank() == 255)
    let members = try await space.members()
    #expect(members.count == 1)
    #expect(members.first?.level == "administer")
    #expect(members.first?.rank == 255)
    #expect(try await space.recoveryMembers().isEmpty)
    let before = try await space.checkpoints()
    #expect(before.inEffect == nil)
    #expect(before.pending.isEmpty)

    // Alone in the space, its administrator votes by the checkpoint itself.
    let checkpoint = try await space.proposeCheckpoint()
    #expect(try await space.checkpoints().following == checkpoint)
    #expect(try await space.lateChanges().isEmpty)

    // A device of no person has no device list to checkpoint.
    let list = await device.listCheckpoints()
    #expect(list.inEffect == nil && list.pending.isEmpty)
    await #expect(throws: FrasilError.self) {
        _ = try await device.proposeListCheckpoint()
    }

    following.cancel()
    try await device.shutdown()
}

@Test func aWrongUnlockKeyIsAnError() async throws {
    await #expect(throws: FrasilError.self) {
        _ = try await Device.openInMemory(unlockKey: Data())
    }
}
