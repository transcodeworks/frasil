import AVFoundation
import Foundation
import Frasil

// A sample to copy into an application, not part of the package: it backs an
// `AVURLAsset` with a blob, so that a player plays a blob the device does not
// hold whole and fetches only what it reads.
//
//     let loader = BlobResourceLoader(
//         blobs: blobs, blob: blob, contentType: UTType.mpeg4Movie.identifier)
//     let asset = AVURLAsset(url: URL(string: "frasil-blob://\(blob)")!)
//     asset.resourceLoader.setDelegate(loader, queue: DispatchQueue(label: "blob-loader"))
//     let player = AVPlayer(playerItem: AVPlayerItem(asset: asset))
//
// The URL's scheme is one AVFoundation does not load by itself, so every
// request comes to the delegate. Keep the loader for as long as the asset
// lives: the asset holds its delegate weakly. Call `cancelAll()` when the
// player is done with the asset.
//
// One reader for each request. A player has several requests open at a
// time, at different places in the file: the start, an index at the end,
// and where it plays. A reader serves one call at a time and fetches ahead
// of the place it last read, so requests that share one take turns, each
// waits for the other's fetch, and each jump between them drops what the
// reader had asked for ahead. With a reader of its own, a request reads in
// order from its offset, the reader fetches ahead of it, and ending the
// request ends its fetches. A reader costs nothing until it is read, and
// what one request fetched is in the device's cache for the next, unless
// the readers store nothing (`uncached`).
//
// Memory. AVFoundation keeps what a request is answered and gives no sign
// of how much it has used, so a request to the end of the resource takes the
// rest of the blob as fast as the device fetches it. The loader answers in
// pieces of at most a chunk and stops between pieces when the request is
// cancelled, which bounds what the loader itself holds to one piece. To
// bound what AVFoundation holds of a long resource, give the loader a
// `bytesPerSecond` a few times the resource's bit rate: it then answers no
// faster than that, and the player cancels the request when it seeks or
// stops.

/// One request of a player's: what it asks, and where the answer goes.
/// `AVAssetResourceLoadingRequest` is one (`AssetLoadingRequest`).
protocol BlobLoadingRequest: AnyObject, Sendable {
    /// Whether the request asks what the resource is.
    var wantsContentInformation: Bool { get }
    /// The bytes the request asks for: from `offset`, `length` of them or,
    /// with none, to the resource's end. None for a request of no bytes.
    var range: (offset: UInt64, length: UInt64?)? { get }
    /// Answers what the resource is: its uniform type identifier, its
    /// length, and that any range of it can be asked for.
    func inform(contentType: String, length: UInt64)
    /// Gives the next bytes of the range, in order.
    func respond(with data: Data)
    /// Ends the request: with no error once every byte was given.
    func finish(with error: Error?)
}

/// Answers a player's requests from a blob, each through a reader of its own.
final class BlobResourceLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    /// The most one answer holds: about a chunk.
    static let largestPiece: UInt64 = 1 << 20

    private let blobs: Blobs
    private let blob: String
    private let read: ReadOptions?
    private let contentType: String
    private let piece: UInt64
    private let readAhead: UInt64?
    private let bytesPerSecond: UInt64?
    private let lock = NSLock()
    /// The requests being answered, each with what cancels it. A request is
    /// answered only while it is here, and only under the lock: once
    /// `cancel` has taken it out, nothing more reaches it.
    private var loading: [ObjectIdentifier: (task: Task<Void, Never>, cancellation: Cancellation)] = [:]
    /// The blob's size, once a request has learned it.
    private var size: UInt64?

    /// A loader of `blob` in `blobs` for a resource of the uniform type
    /// `contentType`, such as `public.mpeg-4`. Each request's reader is
    /// opened with `read`, and fetches `readAhead` chunks ahead, or the
    /// reader's default with none. It answers `piece` bytes at a time, at
    /// most `largestPiece`, so that a player gets bytes as they arrive and a
    /// cancelled request stops within one piece; and no faster than
    /// `bytesPerSecond`, if given.
    init(
        blobs: Blobs, blob: String, read: ReadOptions? = nil, contentType: String,
        piece: UInt64 = 256 * 1024, readAhead: UInt64? = nil, bytesPerSecond: UInt64? = nil
    ) {
        self.blobs = blobs
        self.blob = blob
        self.read = read
        self.contentType = contentType
        self.piece = min(max(piece, 1), Self.largestPiece)
        self.readAhead = readAhead
        self.bytesPerSecond = bytesPerSecond.map { max($0, 1) }
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        start(AssetLoadingRequest(loadingRequest), key: ObjectIdentifier(loadingRequest))
        return true
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        cancel(key: ObjectIdentifier(loadingRequest))
    }

    /// Answers `request` on a task of its own.
    func start(_ request: BlobLoadingRequest, key: ObjectIdentifier) {
        let cancellation = Cancellation()
        lock.lock()
        defer { lock.unlock() }
        // The task answers nothing before it is listed: it takes the lock
        // for each answer.
        let task = Task { [self] in
            var failure: Error?
            do {
                try await serve(request, key: key, cancellation: cancellation)
            } catch {
                failure = error
            }
            // A cancelled request is not answered again.
            answer(key, last: true) { request.finish(with: failure) }
        }
        loading[key] = (task, cancellation)
    }

    /// Stops answering a request: the read it waits for ends at once, and
    /// the request is given nothing after this returns. The task that
    /// answered it, to wait for in a test.
    @discardableResult
    func cancel(key: ObjectIdentifier) -> Task<Void, Never>? {
        lock.lock()
        let cancelled = loading.removeValue(forKey: key)
        lock.unlock()
        cancelled?.cancellation.cancel()
        cancelled?.task.cancel()
        return cancelled?.task
    }

    /// Stops answering every request.
    func cancelAll() {
        lock.lock()
        let cancelled = loading
        loading.removeAll()
        lock.unlock()
        for (task, cancellation) in cancelled.values {
            cancellation.cancel()
            task.cancel()
        }
    }

    /// Answers the request of `key` with `give`, unless it was cancelled:
    /// the lock orders each answer before or after `cancel`, never across
    /// it. With `last`, the request is forgotten.
    @discardableResult
    private func answer(_ key: ObjectIdentifier, last: Bool = false, _ give: () -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard loading[key] != nil else { return false }
        if last { loading.removeValue(forKey: key) }
        give()
        return true
    }

    private func serve(
        _ request: BlobLoadingRequest, key: ObjectIdentifier, cancellation: Cancellation
    ) async throws {
        let reader = try await blobs.openReader(id: blob, read: read)
        if let readAhead { reader.setReadAhead(chunks: readAhead) }
        do {
            try await serve(request, key: key, from: reader, cancellation: cancellation)
        } catch {
            try? await reader.end()
            throw error
        }
        try await reader.end()
    }

    private func serve(
        _ request: BlobLoadingRequest, key: ObjectIdentifier, from reader: BlobReader,
        cancellation: Cancellation
    ) async throws {
        var offset = request.range?.offset ?? 0
        // The first piece, read before the size is asked for: the read
        // opens the chunk the request starts in, and the size comes with it.
        var first: Data?
        if let range = request.range, range.length != 0 {
            first = try await reader.readAt(
                offset: offset, length: min(piece, range.length ?? piece),
                cancellation: cancellation)
        }
        let size = try await size(of: reader, cancellation: cancellation)
        if request.wantsContentInformation {
            guard answer(key, { request.inform(contentType: contentType, length: size) }) else {
                throw CancellationError()
            }
        }
        guard let range = request.range else { return }
        let end = range.length.map { min(size, range.offset + $0) } ?? size
        let started = DispatchTime.now().uptimeNanoseconds
        while offset < end {
            let data: Data
            if let read = first {
                data = read
                first = nil
            } else {
                data = try await reader.readAt(
                    offset: offset, length: min(piece, end - offset), cancellation: cancellation)
            }
            // Fewer bytes than asked are the blob's end, or what a read had
            // before a chunk that failed: the next read reports the failure.
            if data.isEmpty { break }
            guard answer(key, { request.respond(with: data) }) else { throw CancellationError() }
            offset += UInt64(data.count)
            if let bytesPerSecond, offset < end {
                // No faster than the rate: wait until the bytes given so far
                // are due. The wait ends at once when the request is
                // cancelled.
                let given = offset - range.offset
                let due = started + given * 1_000_000_000 / bytesPerSecond
                let now = DispatchTime.now().uptimeNanoseconds
                if due > now { try await Task.sleep(nanoseconds: due - now) }
            }
        }
    }

    /// The blob's size: what a request learned before, or what `reader`
    /// knows from its first read, or fetched.
    private func size(of reader: BlobReader, cancellation: Cancellation) async throws -> UInt64 {
        if let known = lock.withLock({ size }) { return known }
        let learned: UInt64
        if let known = reader.size() {
            learned = known
        } else {
            learned = try await reader.fetchSize(cancellation: cancellation)
        }
        lock.withLock { size = learned }
        return learned
    }
}

/// A player's request, as the loader reads and answers it.
final class AssetLoadingRequest: BlobLoadingRequest, @unchecked Sendable {
    private let request: AVAssetResourceLoadingRequest

    init(_ request: AVAssetResourceLoadingRequest) {
        self.request = request
    }

    var wantsContentInformation: Bool { request.contentInformationRequest != nil }

    var range: (offset: UInt64, length: UInt64?)? {
        guard let data = request.dataRequest else { return nil }
        // Where the request stands, should part of it have been answered.
        let offset = UInt64(max(data.currentOffset, 0))
        if data.requestsAllDataToEndOfResource { return (offset, nil) }
        let end = UInt64(max(data.requestedOffset, 0)) + UInt64(max(data.requestedLength, 0))
        return (offset, end > offset ? end - offset : 0)
    }

    func inform(contentType: String, length: UInt64) {
        guard let information = request.contentInformationRequest else { return }
        information.contentType = contentType
        information.contentLength = Int64(clamping: length)
        information.isByteRangeAccessSupported = true
    }

    func respond(with data: Data) {
        request.dataRequest?.respond(with: data)
    }

    func finish(with error: Error?) {
        if let error {
            request.finishLoading(with: error)
        } else {
            request.finishLoading()
        }
    }
}
