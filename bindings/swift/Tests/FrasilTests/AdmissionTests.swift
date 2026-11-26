import Foundation
import Testing
@testable import Frasil

/// What a listener of the tests throws.
private struct ScreenGone: Error {}

/// A listener that notes what it is shown, then answers, throws, or waits
/// until it is released and answers then.
private final class Asks: AdmissionListener, @unchecked Sendable {
    private let answer: Bool?
    private let gate: DispatchSemaphore?
    private let lock = NSLock()
    private var seen: (code: String, name: String)?
    private var back = false

    /// Answers `answer`, or throws for none; waits for `release()` first
    /// when `held`.
    init(_ answer: Bool?, held: Bool = false) {
        self.answer = answer
        self.gate = held ? DispatchSemaphore(value: 0) : nil
    }

    func confirm(code: String, name: String) throws -> Bool {
        lock.withLock { seen = (code, name) }
        gate?.wait()
        lock.withLock { back = true }
        guard let answer else { throw ScreenGone() }
        return answer
    }

    /// Lets a held listener answer.
    func release() { gate?.signal() }

    /// The code and the name the listener was shown, if it was asked.
    var shown: (code: String, name: String)? { lock.withLock { seen } }

    /// Whether the listener gave its answer.
    var returned: Bool { lock.withLock { back } }
}

/// Waits up to thirty seconds until `check` gives a value.
private func eventually<T: Sendable>(
    _ what: String, _ check: @Sendable () async throws -> T?
) async throws -> T {
    for _ in 0..<600 {
        if let found = try? await check() { return found }
        try await Task.sleep(nanoseconds: 50_000_000)
    }
    Issue.record("not in time: \(what)")
    throw CancellationError()
}

/// The failure of `call`, which must fail, as text.
private func failure<T>(_ call: () async throws -> T) async -> String {
    do {
        _ = try await call()
        Issue.record("the call did not fail")
        return ""
    } catch {
        return String(describing: error)
    }
}

/// A device that administers a space, and one that is to join it, both on
/// loopback with no peer.
private struct Pair {
    let host: Device
    let newcomer: Device
    let space: Space

    static func make(key: UInt8) async throws -> Pair {
        let host = try await Device.openInMemory(
            unlockKey: Data(repeating: key, count: 32), options: DeviceOptions(loopback: true))
        let newcomer = try await Device.openInMemory(
            unlockKey: Data(repeating: key + 1, count: 32), options: DeviceOptions(loopback: true))
        return Pair(host: host, newcomer: newcomer, space: try await host.createSpace())
    }

    /// Whether the space names the newcomer a member, as the host has it.
    func admitted() async throws -> Bool {
        try await space.members().contains { $0.id == newcomer.id() }
    }

    func close() async throws {
        try await newcomer.shutdown()
        try await host.shutdown()
    }
}

@Test func aNewcomerJoinsOnceBothConfirmOneCode() async throws {
    let pair = try await Pair.make(key: 110)
    let (hosts, joins) = (Asks(true), Asks(true))
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: hosts)
    let joined = try await pair.newcomer.join(
        invitation: invitation.text(), name: "newcomer", listener: joins)
    try await invitation.admitted()

    // Both listeners were shown one code of six digits, each with the name
    // the other device gave.
    let (host, newcomer) = (try #require(hosts.shown), try #require(joins.shown))
    #expect(host.code == newcomer.code)
    #expect(host.code.count == 6 && host.code.allSatisfy(\.isNumber))
    #expect(host.name == "newcomer" && newcomer.name == "host")

    #expect(joined.id() == pair.space.id())
    let member = try #require(try await pair.space.members().first { $0.id == pair.newcomer.id() })
    #expect(member.level == "write")

    // The invitation admitted its newcomer: it is spent, and says so.
    let spent = await failure { try await invitation.admitted() }
    #expect(spent.contains("the invitation is spent") && spent.contains("invite again"))
    try await pair.close()
}

@Test func aNearbyAdmissionMakesNoAdministrator() async throws {
    let pair = try await Pair.make(key: 120)
    let refused = await failure {
        try await pair.space.invite(level: "administer", name: "host", listener: Asks(true))
    }
    #expect(refused.contains("read or write") && refused.contains("raise"))
    try await pair.close()
}

@Test func theInvitersNoRefusesTheNewcomer() async throws {
    let pair = try await Pair.make(key: 130)
    let (hosts, joins) = (Asks(false), Asks(true))
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: hosts)
    await #expect(throws: FrasilError.self) {
        _ = try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: joins)
    }
    await #expect(throws: FrasilError.self) { try await invitation.admitted() }
    #expect(hosts.shown?.code == joins.shown?.code && hosts.shown != nil)
    #expect(try await pair.admitted() == false)
    #expect(await pair.newcomer.spaces().isEmpty)
    try await pair.close()
}

@Test func theNewcomersNoRefusesIt() async throws {
    let pair = try await Pair.make(key: 140)
    // The newcomer's person answers once both listeners are asked.
    let (hosts, joins) = (Asks(true), Asks(false, held: true))
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: hosts)
    let joining = Task {
        try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: joins)
    }
    let shown = try await eventually("the inviter's listener is asked") { hosts.shown }
    let asked = try await eventually("the newcomer's listener is asked") { joins.shown }
    #expect(shown.code == asked.code)
    joins.release()
    await #expect(throws: FrasilError.self) { _ = try await joining.value }
    #expect(await pair.newcomer.spaces().isEmpty)
    try await pair.close()
}

@Test func aListenerThatThrowsRefuses() async throws {
    // The inviter's listener throws: the newcomer is no member.
    let pair = try await Pair.make(key: 150)
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: Asks(nil))
    await #expect(throws: FrasilError.self) {
        _ = try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: Asks(true))
    }
    await #expect(throws: FrasilError.self) { try await invitation.admitted() }
    #expect(try await pair.admitted() == false)
    try await pair.close()

    // The newcomer's listener throws: it joins nothing.
    let other = try await Pair.make(key: 160)
    let second = try await other.space.invite(level: "write", name: "host", listener: Asks(true))
    await #expect(throws: FrasilError.self) {
        _ = try await other.newcomer.join(
            invitation: second.text(), name: "newcomer", listener: Asks(nil))
    }
    #expect(await other.newcomer.spaces().isEmpty)
    try await other.close()
}

@Test func aCancelledWaitAbandonsItsInvitation() async throws {
    let pair = try await Pair.make(key: 170)
    // The inviter's person never answers.
    let hosts = Asks(true, held: true)
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: hosts)
    let cancellation = Cancellation()
    let waiting = Task { try await invitation.admitted(cancellation: cancellation) }
    let joining = Task {
        try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: Asks(true))
    }
    _ = try await eventually("the inviter's listener is asked") { hosts.shown }

    // Cancelled while its listener is asked: the wait fails, and the
    // newcomer is refused without the listener's answer.
    cancellation.cancel()
    let cancelled = await failure { try await waiting.value }
    #expect(cancelled.contains("the admission was cancelled"))
    await #expect(throws: FrasilError.self) { _ = try await joining.value }
    #expect(!hosts.returned)
    #expect(try await pair.admitted() == false)
    #expect(await pair.newcomer.spaces().isEmpty)

    // The invitation is spent, and says why.
    let spent = await failure { try await invitation.admitted() }
    #expect(spent.contains("the invitation is spent") && spent.contains("was cancelled"))

    // The listener's late answer counts for nothing.
    hosts.release()
    _ = try await eventually("the listener returns") { hosts.returned ? true : nil }
    #expect(try await pair.admitted() == false)
    try await pair.close()
}

@Test func aCancelledJoinJoinsNothing() async throws {
    let pair = try await Pair.make(key: 180)
    // The inviter's person does not confirm: a device that confirmed has
    // granted, whatever the newcomer does after.
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: Asks(false))
    // The newcomer's person never answers.
    let joins = Asks(true, held: true)
    let cancellation = Cancellation()
    let joining = Task {
        try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: joins,
            cancellation: cancellation)
    }
    _ = try await eventually("the newcomer's listener is asked") { joins.shown }
    cancellation.cancel()
    let cancelled = await failure { try await joining.value }
    #expect(cancelled.contains("the admission was cancelled"))
    #expect(!joins.returned)
    #expect(await pair.newcomer.spaces().isEmpty)
    joins.release()
    _ = try await eventually("the listener returns") { joins.returned ? true : nil }
    #expect(await pair.newcomer.spaces().isEmpty)

    // A join given a cancellation that was cancelled before fails at once.
    let late = await failure {
        try await pair.newcomer.join(
            invitation: invitation.text(), name: "newcomer", listener: Asks(true),
            cancellation: cancellation)
    }
    #expect(late.contains("cancelled"))

    // The device joins by a new invitation.
    let again = try await pair.space.invite(level: "read", name: "host", listener: Asks(true))
    let joined = try await pair.newcomer.join(
        invitation: again.text(), name: "newcomer", listener: Asks(true))
    try await again.admitted()
    #expect(joined.id() == pair.space.id())
    let member = try #require(try await pair.space.members().first { $0.id == pair.newcomer.id() })
    #expect(member.level == "read")
    try await pair.close()
}

@Test func aMemberOfOneSpaceIsAdmittedToAnotherWithNoPeer() async throws {
    let pair = try await Pair.make(key: 150)
    let invitation = try await pair.space.invite(level: "write", name: "host", listener: Asks(true))
    _ = try await pair.newcomer.join(
        invitation: invitation.text(), name: "newcomer", listener: Asks(true))
    try await invitation.admitted()

    // The host admits the newcomer, a direct member of the first space, to a
    // second one, with no code; the welcome goes over the member connection
    // the two hold for the first.
    let other = try await pair.host.createSpace()
    let administer = await failure {
        try await other.admitMember(
            knownSpace: pair.space.id(), member: pair.newcomer.id(), level: "administer")
    }
    #expect(administer.contains("admitMemberAdministrator"))
    try await other.admitMember(
        knownSpace: pair.space.id(), member: pair.newcomer.id(), level: "read")
    let member = try #require(try await other.members().first { $0.id == pair.newcomer.id() })
    #expect(member.level == "read")
    let (newcomer, id) = (pair.newcomer, pair.newcomer.id())
    let otherId = other.id()
    let arrived = try await eventually("the newcomer follows the second space") {
        let space = try await newcomer.space(id: otherId)
        return try await space.members().contains { $0.id == id } ? space : nil
    }
    #expect(arrived.id() == other.id())

    // A device that is a member already is not admitted again.
    _ = await failure {
        try await other.admitMemberAdministrator(
            knownSpace: pair.space.id(), member: pair.newcomer.id(), rank: 1)
    }
    try await pair.close()
}
