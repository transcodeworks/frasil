@preconcurrency import AVFoundation
import Foundation
import Testing
@testable import Frasil

/// The plaintext a chunk holds.
private let chunk: UInt64 = 1_048_536

/// Confirms every admission code: both devices are the test's.
private final class Confirms: AdmissionListener {
    func confirm(code: String, name: String) -> Bool { true }
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

/// What `within` fails with when its time is up.
private struct TimedOut: Error {
    let what: String
}

/// Resumes a continuation once, whoever comes first.
private final class Once<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(with result: Result<T, Error>) {
        let waiting = lock.withLock {
            let waiting = continuation
            continuation = nil
            return waiting
        }
        waiting?.resume(with: result)
    }
}

/// Runs `body`, and fails after `seconds` if it has not ended by then, even
/// when what it waits for takes no notice of being cancelled.
private func within<T: Sendable>(
    seconds: UInt64, _ what: String, _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        let once = Once(continuation)
        let work = Task {
            do {
                once.resume(with: .success(try await body()))
            } catch {
                once.resume(with: .failure(error))
            }
        }
        Task {
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            work.cancel()
            once.resume(with: .failure(TimedOut(what: what)))
        }
    }
}

/// Bytes that differ from place to place.
private func patterned(count: Int) -> Data {
    var bytes = Data(count: count)
    for index in bytes.indices { bytes[index] = UInt8(truncatingIfNeeded: index &* 31 &+ index >> 16) }
    return bytes
}

/// Two devices on loopback with no peer: one holds a blob of five chunks
/// and a bit, and the other, a member of its space, holds nothing of it.
private struct Scene {
    let holder: Device
    let device: Device
    /// The blob stream on the device that holds nothing of the blob.
    let blobs: Blobs
    let blob: String
    let bytes: Data

    static func make(
        key: UInt8, options: DeviceOptions = DeviceOptions(loopback: true), bytes: Data? = nil
    ) async throws -> Scene {
        let holder = try await Device.openInMemory(
            unlockKey: Data(repeating: key, count: 32), options: DeviceOptions(loopback: true))
        let space = try await holder.createSpace()
        let files = try space.createBlobs()
        let device = try await Device.openInMemory(
            unlockKey: Data(repeating: key + 1, count: 32), options: options)
        let invitation = try await space.invite(level: "write", name: "holder", listener: Confirms())
        let joined = try await device.join(
            invitation: invitation.text(), name: "reader", listener: Confirms())
        try await invitation.admitted()

        let bytes = bytes ?? patterned(count: Int(chunk) * 5 + 300_000)
        let blob = try await files.put(name: "film.mp4", bytes: bytes)
        let blobs = try await eventually("the stream arrives") { try await joined.blobs(id: files.id()) }
        // Listed, with its holder connected, and nothing of it here.
        _ = try await eventually("the blob is listed") {
            try await blobs.status(id: blob) == .absent ? true : nil
        }
        let local = try await blobs.local(id: blob)
        #expect(local == BlobLocal(state: .absent, bytes: 0, size: UInt64(bytes.count)))
        return Scene(holder: holder, device: device, blobs: blobs, blob: blob, bytes: bytes)
    }

    func slice(_ offset: UInt64, _ length: UInt64) -> Data {
        bytes.subdata(in: Int(offset)..<Int(min(offset + length, UInt64(bytes.count))))
    }

    func close() async throws {
        try await device.shutdown()
        try await holder.shutdown()
    }
}

/// A request as a player makes one, which keeps what it is answered.
private final class Request: BlobLoadingRequest, @unchecked Sendable {
    let wantsContentInformation: Bool
    let range: (offset: UInt64, length: UInt64?)?
    private let lock = NSLock()
    private var information: (contentType: String, length: UInt64)?
    private var data = Data()
    private var pieces = 0
    private var finished: Result<Void, Error>?

    init(information: Bool = false, range: (offset: UInt64, length: UInt64?)?) {
        self.wantsContentInformation = information
        self.range = range
    }

    func inform(contentType: String, length: UInt64) {
        lock.withLock { information = (contentType, length) }
    }

    func respond(with data: Data) {
        lock.withLock {
            self.data.append(data)
            pieces += 1
        }
    }

    func finish(with error: Error?) {
        lock.withLock { finished = error.map { .failure($0) } ?? .success(()) }
    }

    /// What the request was answered so far.
    struct Answered {
        let information: (contentType: String, length: UInt64)?
        let data: Data
        let pieces: Int
        let finished: Bool
    }

    var answered: Answered {
        lock.withLock {
            Answered(information: information, data: data, pieces: pieces, finished: finished != nil)
        }
    }

    /// The bytes the request was given, once it finished without an error.
    func loaded() async throws -> Data {
        let result = try await eventually("the request finishes") { self.lock.withLock { self.finished } }
        try result.get()
        return answered.data
    }
}

private func load(_ loader: BlobResourceLoader, _ request: Request) async throws -> Data {
    loader.start(request, key: ObjectIdentifier(request))
    return try await request.loaded()
}

@Test func aPlayerReadsABlobThatIsNotWholeHere() async throws {
    let scene = try await Scene.make(key: 10)
    let size = UInt64(scene.bytes.count)
    // Each request reads through a reader of its own. No read-ahead here, so
    // that the device fetches the chunks that are read and no other, and the
    // test can say which.
    let loader = BlobResourceLoader(
        blobs: scene.blobs, blob: scene.blob, contentType: "public.mpeg-4", piece: 100_000,
        readAhead: 0)

    // A player first asks what the resource is, with its first two bytes.
    let first = Request(information: true, range: (0, 2))
    #expect(try await load(loader, first) == scene.slice(0, 2))
    #expect(first.answered.information?.contentType == "public.mpeg-4")
    #expect(first.answered.information?.length == size)

    // A seek to the middle, over the end of one chunk and into the next,
    // answered in pieces.
    let middle = Request(range: (chunk * 3 - 150_000, 300_000))
    #expect(try await load(loader, middle) == scene.slice(chunk * 3 - 150_000, 300_000))
    #expect(middle.answered.pieces == 3)

    // The end of the blob, asked for as everything from an offset on, a
    // range that reaches past the end, and one that starts at the end.
    let end = Request(range: (size - 70_000, nil))
    #expect(try await load(loader, end) == scene.slice(size - 70_000, 70_000))
    let past = Request(range: (size - 10, 4096))
    #expect(try await load(loader, past) == scene.slice(size - 10, 10))
    let none = Request(information: true, range: (size, nil))
    #expect(try await load(loader, none).isEmpty)
    #expect(none.answered.information?.length == size)

    // The chunks that were read are in the cache, and the blob is not whole
    // here: the chunks between them were never fetched.
    let local = try await scene.blobs.local(id: scene.blob)
    #expect(local.state == .cached)
    #expect(local.bytes > 0 && local.bytes < size - chunk)
    #expect(try await scene.blobs.status(id: scene.blob) != .readable)
    #expect(try await scene.blobs.get(id: scene.blob, read: ReadOptions(local: true)) == nil)
    let usage = await scene.device.blobCacheUsage()
    #expect(usage.cached == local.bytes && usage.kept == 0 && usage.budget == 256 << 20)

    // A loader with a rate answers no faster: three pieces of 50,000 bytes
    // at 500,000 bytes a second take two tenths of a second or more.
    let paced = BlobResourceLoader(
        blobs: scene.blobs, blob: scene.blob, contentType: "public.mpeg-4", piece: 50_000,
        readAhead: 0, bytesPerSecond: 500_000)
    let slow = Request(range: (0, 150_000))
    let began = DispatchTime.now().uptimeNanoseconds
    #expect(try await load(paced, slow) == scene.slice(0, 150_000))
    #expect(slow.answered.pieces == 3)
    #expect(DispatchTime.now().uptimeNanoseconds - began >= 200_000_000)

    // A reader by itself: it knows no size before its first read, says how
    // far what it gave was checked, and fails every read once it is ended.
    let reader = try await scene.blobs.openReader(id: scene.blob)
    reader.setReadAhead(chunks: 0)
    #expect(reader.readAhead() == 0)
    #expect(reader.size() == nil)
    #expect(try await reader.readAt(offset: chunk - 3, length: 6) == scene.slice(chunk - 3, 6))
    #expect(reader.size() == size)
    #expect(reader.verified() == .chunks)

    // A read is at most 64 MiB: one byte more is refused, and says so.
    #expect(try await reader.readAt(offset: size - 4, length: 64 << 20) == scene.slice(size - 4, 4))
    do {
        _ = try await reader.readAt(offset: 0, length: (64 << 20) + 1)
        Issue.record("a read longer than the cap was made")
    } catch {
        #expect(String(describing: error).contains("at most 67108864 bytes"))
    }

    try await reader.end()
    await #expect(throws: FrasilError.self) {
        _ = try await reader.readAt(offset: 0, length: 1)
    }
    try await scene.close()
}

@Test func aCancelledRequestStopsAndIsGivenNothingMore() async throws {
    // A budget of zero: every read passes through memory.
    let scene = try await Scene.make(key: 20, options: DeviceOptions(blobCache: 0, loopback: true))
    let size = UInt64(scene.bytes.count)
    // At this rate the whole blob takes over a minute: the request below is
    // not at its end when its first bytes are seen, however slow the test
    // runs.
    let loader = BlobResourceLoader(
        blobs: scene.blobs, blob: scene.blob, read: ReadOptions(uncached: true),
        contentType: "public.mpeg-4", piece: 64 * 1024, readAhead: 0, bytesPerSecond: 64 * 1024)

    // A player asks for the whole blob, then gives the request up once its
    // first bytes arrive.
    let whole = Request(range: (0, nil))
    loader.start(whole, key: ObjectIdentifier(whole))
    _ = try await eventually("the first bytes arrive") { whole.answered.pieces > 0 ? true : nil }
    let answering = loader.cancel(key: ObjectIdentifier(whole))
    // Nothing reaches the request once `cancel` has returned: what it holds
    // now is what it holds when the task that answered it has ended.
    let given = whole.answered
    #expect(!given.finished)
    #expect(UInt64(given.data.count) < size)
    #expect(given.data == scene.slice(0, UInt64(given.data.count)))
    await answering?.value
    #expect(whole.answered.pieces == given.pieces)
    #expect(!whole.answered.finished)

    // Another request reads on, through a reader of its own.
    let after = Request(range: (chunk * 2 + 5, 1000))
    #expect(try await load(loader, after) == scene.slice(chunk * 2 + 5, 1000))

    // A read given a cancellation that was cancelled before fails at once,
    // and its reader reads on.
    let reader = try await scene.blobs.openReader(id: scene.blob, read: ReadOptions(uncached: true))
    reader.setReadAhead(chunks: 0)
    let cancelled = Cancellation()
    cancelled.cancel()
    #expect(cancelled.isCancelled())
    await #expect(throws: FrasilError.self) {
        _ = try await reader.readAt(offset: 0, length: 10, cancellation: cancelled)
    }
    #expect(try await reader.readAt(offset: size - 5, length: 100) == scene.slice(size - 5, 5))

    // That a read which waits for a chunk ends when its cancellation is
    // cancelled, and when its reader is ended, is tested in the crate
    // (`a_waiting_read_ends_when_it_is_cancelled` and
    // `a_waiting_read_ends_when_its_reader_is_ended` in
    // crates/frasil-uniffi/src/reads.rs), where a read can be held waiting;
    // here a read may have ended before either reaches it.

    // Every reader ended: nothing of the blob stays on the device.
    try await reader.end()
    #expect(try await scene.blobs.local(id: scene.blob).state == .absent)
    let usage = await scene.device.blobCacheUsage()
    #expect(usage == BlobCacheUsage(budget: 0, cached: 0, kept: 0))
    try await scene.close()
}

@Test func aDeviceKeepsAndDropsABlob() async throws {
    let scene = try await Scene.make(key: 30, options: DeviceOptions(blobCache: 64 << 20, loopback: true))
    let size = UInt64(scene.bytes.count)
    // Nothing is fetched for a local read.
    #expect(try await scene.blobs.getRange(
        id: scene.blob, offset: 0, length: 10, read: ReadOptions(local: true)) == nil)
    #expect(try await scene.blobs.contentHash(id: scene.blob, read: ReadOptions(local: true)) == nil)

    // A range read fetches the chunk it lies in, into the cache.
    #expect(try await scene.blobs.getRange(id: scene.blob, offset: chunk + 7, length: 9)
        == scene.slice(chunk + 7, 9))
    let part = try await scene.blobs.local(id: scene.blob)
    #expect(part.state == .cached && part.bytes > 0 && part.bytes < size)

    // Kept: fetched whole, and outside the cache's budget.
    try await scene.blobs.keep(id: scene.blob, listener: nil)
    let kept = try await scene.blobs.local(id: scene.blob)
    #expect(kept.state == .kept && kept.bytes > size)
    #expect(try await scene.blobs.status(id: scene.blob) == .readable)
    let usage = await scene.device.blobCacheUsage()
    #expect(usage == BlobCacheUsage(budget: 64 << 20, cached: 0, kept: kept.bytes))
    #expect(try await scene.blobs.get(id: scene.blob, read: ReadOptions(local: true)) == scene.bytes)

    // Dropped: absent again, and nothing of it is stored.
    try await scene.blobs.dropLocal(id: scene.blob)
    #expect(try await scene.blobs.local(id: scene.blob)
        == BlobLocal(state: .absent, bytes: 0, size: size))
    #expect(try await scene.blobs.get(id: scene.blob, read: ReadOptions(local: true)) == nil)
    #expect(await scene.device.blobCacheUsage().kept == 0)

    // Another device put the blob: no change of this device's waits.
    #expect(try await scene.blobs.isDurable(id: scene.blob))
    #expect(try await scene.blobs.pending().isEmpty)
    try await scene.close()
}

@Test func aReadSaysWhatBecomesOfABlob() async throws {
    let scene = try await Scene.make(key: 40)
    // A read that stores nothing leaves the blob absent.
    #expect(try await scene.blobs.get(id: scene.blob, read: ReadOptions(uncached: true)) == scene.bytes)
    _ = try await eventually("nothing stays of a read that stores nothing") {
        try await scene.blobs.local(id: scene.blob).state == .absent ? true : nil
    }
    let hash = try #require(
        try await scene.blobs.contentHash(id: scene.blob, read: ReadOptions(uncached: true)))
    #expect(hash.count == 32)

    // A read that keeps: the blob stays, whole, outside the budget.
    let path = FileManager.default.temporaryDirectory
        .appendingPathComponent("frasil-reads-\(UUID().uuidString)")
    try await scene.blobs.getToFile(
        id: scene.blob, path: path.path, listener: nil, read: ReadOptions(keep: true))
    #expect(try Data(contentsOf: path) == scene.bytes)
    try? FileManager.default.removeItem(at: path)
    #expect(try await scene.blobs.local(id: scene.blob).state == .kept)
    #expect(try await scene.blobs.status(id: scene.blob) == .readable)

    // A reader over a blob that is whole here reads it from the device, and
    // every check has run on it.
    let reader = try await scene.blobs.openReader(id: scene.blob, read: ReadOptions(local: true))
    #expect(try await reader.fetchSize() == UInt64(scene.bytes.count))
    #expect(try await reader.readAt(offset: chunk - 3, length: 6) == scene.slice(chunk - 3, 6))
    _ = try await eventually("the whole blob was checked") { reader.verified() == .whole ? true : nil }
    try await reader.end()
    try await scene.close()
}

/// The sample rate of the test's sound.
private let rate = 44_100

/// A sound file: a WAVE header, then `samples` samples of 16-bit mono PCM.
private func wave(samples: Int) -> Data {
    func little<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
    let sound = patterned(count: samples * 2)
    var file = Data("RIFF".utf8) + little(UInt32(36 + sound.count)) + Data("WAVEfmt ".utf8)
    file += little(UInt32(16)) + little(UInt16(1)) + little(UInt16(1))
    file += little(UInt32(rate)) + little(UInt32(rate * 2)) + little(UInt16(2)) + little(UInt16(16))
    file += Data("data".utf8) + little(UInt32(sound.count))
    return file + sound
}

/// The stored samples of an asset's first sound track from `start`, `count`
/// of them, as AVFoundation reads them through the asset's loader.
private func samples(of asset: AVURLAsset, from start: Int, count: Int) async throws -> Data {
    let track = try #require(try await asset.loadTracks(withMediaType: .audio).first)
    return try await withCheckedThrowingContinuation { continuation in
        // The reader waits for each buffer: on a thread of its own.
        DispatchQueue.global().async {
            do {
                let reader = try AVAssetReader(asset: asset)
                reader.timeRange = CMTimeRange(
                    start: CMTime(value: Int64(start), timescale: Int32(rate)),
                    duration: CMTime(value: Int64(count), timescale: Int32(rate)))
                // No settings: the samples as the file stores them.
                let output = AVAssetReaderTrackOutput(track: track, outputSettings: nil)
                reader.add(output)
                guard reader.startReading() else { throw reader.error ?? CancellationError() }
                var read = Data()
                while let buffer = output.copyNextSampleBuffer() {
                    guard let block = CMSampleBufferGetDataBuffer(buffer) else { continue }
                    var bytes = Data(count: CMBlockBufferGetDataLength(block))
                    let length = bytes.count
                    let status = bytes.withUnsafeMutableBytes {
                        CMBlockBufferCopyDataBytes(
                            block, atOffset: 0, dataLength: length, destination: $0.baseAddress!)
                    }
                    guard status == kCMBlockBufferNoErr else { throw CancellationError() }
                    read += bytes
                }
                if let error = reader.error { throw error }
                continuation.resume(returning: read)
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

@Test func anAssetReadsASoundFileThroughTheLoader() async throws {
    // AVFoundation waits for its loader with no limit of its own: the test
    // fails after a minute instead of waiting with it.
    try await within(seconds: 60, "an asset reads through the loader") {
        let count = (Int(chunk) * 5 + 300_000) / 2
        let file = wave(samples: count)
        let scene = try await Scene.make(key: 50, bytes: file)
        // The loader as an application makes it: a reader for each request,
        // each fetching ahead as a reader does unless told otherwise.
        let loader = BlobResourceLoader(
            blobs: scene.blobs, blob: scene.blob, contentType: "com.microsoft.waveform-audio")
        // A scheme AVFoundation does not load by itself: every request comes
        // to the loader.
        let asset = AVURLAsset(url: try #require(URL(string: "frasil-blob://blob/sound.wav")))
        asset.resourceLoader.setDelegate(loader, queue: DispatchQueue(label: "blob-loader"))

        // AVFoundation learns what the file is from the loader's answers.
        let duration = try await asset.load(.duration)
        #expect(abs(duration.seconds - Double(count) / Double(rate)) < 0.001)

        // A second of sound from the middle, then the last half second: the
        // samples are the file's.
        @Sendable func stored(_ start: Int, _ length: Int) -> Data {
            file.subdata(in: (44 + start * 2)..<(44 + (start + length) * 2))
        }
        #expect(try await samples(of: asset, from: count / 2, count: rate) == stored(count / 2, rate))
        #expect(try await samples(of: asset, from: count - rate / 2, count: rate / 2)
            == stored(count - rate / 2, rate / 2))

        // What AVFoundation asked for came through the device's cache.
        let local = try await scene.blobs.local(id: scene.blob)
        #expect(local.state == .cached && local.bytes > 0)
        loader.cancelAll()
        try await scene.close()
    }
}
