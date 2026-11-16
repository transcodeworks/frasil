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
    let device = try await Device.openInMemory(unlockKey: Data(repeating: 1, count: 32))
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
    let statuses = Statuses()
    let watching = try blobs.observeStatus(id: blob, listener: statuses)
    #expect(try await statuses.heard.until { _ in true } == .readable)
    let hash = try #require(try await blobs.contentHash(id: blob))
    #expect(hash.count == 32)
    _ = try await arrived.heard.until { $0 == .stream(space: space.id(), stream: blobs.id()) }

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
