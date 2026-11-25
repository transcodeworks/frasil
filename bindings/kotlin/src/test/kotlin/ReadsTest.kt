import frasil.AdmissionListener
import frasil.BlobCacheUsage
import frasil.BlobLocal
import frasil.BlobState
import frasil.BlobStatus
import frasil.Blobs
import frasil.Cancellation
import frasil.Device
import frasil.DeviceOptions
import frasil.FrasilException
import frasil.ReadOptions
import frasil.Verified
import java.io.InterruptedIOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The plaintext a chunk holds. */
private const val CHUNK = 1_048_536

/** Confirms every admission code: both devices are the test's. */
private object Confirms : AdmissionListener {
    override fun confirm(code: String, name: String) = true
}

/** Waits up to thirty seconds until [check] gives a value. */
private suspend fun <T : Any> eventually(what: String, check: suspend () -> T?): T {
    repeat(600) {
        runCatching { check() }.getOrNull()?.let { return it }
        delay(50)
    }
    error("not in time: $what")
}

/**
 * Two devices on loopback with no peer: one holds a blob of five chunks and a
 * bit, and the other, a member of its space, holds nothing of it.
 */
private class Scene(
    val holder: Device,
    val device: Device,
    /** The blob stream on the device that holds nothing of the blob. */
    val blobs: Blobs,
    val blob: String,
    val bytes: ByteArray,
) {
    val size get() = bytes.size.toULong()

    fun slice(offset: Int, length: Int) = bytes.copyOfRange(offset, minOf(offset + length, bytes.size))

    suspend fun close() {
        device.shutdown()
        holder.shutdown()
        device.close()
        holder.close()
    }

    companion object {
        suspend fun make(key: Int, options: DeviceOptions = DeviceOptions(loopback = true)): Scene {
            val holder = Device.openInMemory(ByteArray(32) { key.toByte() }, DeviceOptions(loopback = true))
            val space = holder.createSpace()
            val files = space.createBlobs()
            val device = Device.openInMemory(ByteArray(32) { (key + 1).toByte() }, options)
            val invitation = space.invite("write", "holder", Confirms)
            val joined = device.join(invitation.text(), "reader", Confirms)
            invitation.admitted()

            val bytes = ByteArray(CHUNK * 5 + 300_000) { (it * 31 + (it shr 16)).toByte() }
            val blob = files.put("film.mp4", bytes)
            val blobs = eventually("the stream arrives") { joined.blobs(files.id()) }
            // Listed, with its holder connected, and nothing of it here.
            eventually("the blob is listed") { blobs.status(blob).takeIf { it == BlobStatus.Absent } }
            assertEquals(BlobLocal(BlobState.ABSENT, 0uL, bytes.size.toULong()), blobs.local(blob))
            return Scene(holder, device, blobs, blob, bytes)
        }
    }
}

/** Reads a source that was opened until [count] bytes are read or it ends. */
private fun DataSource.readFully(count: Int): ByteArray {
    val out = ByteArray(count)
    var filled = 0
    while (filled < count) {
        // A player reads in buffers of its own size.
        val read = read(out, filled, minOf(8192, count - filled))
        if (read == RESULT_END_OF_INPUT) break
        filled += read
    }
    return out.copyOf(filled)
}

class ReadsTest {
    @Test fun aPlayerReadsABlobThatIsNotWholeHere() = runBlocking {
        val scene = Scene.make(10)
        // Each open reads through a reader of its own. No read-ahead here, so
        // that the device fetches the chunks that are read and no other, and
        // the test can say which.
        val source = BlobDataSource(scene.blobs, scene.blob, piece = 100_000, readAhead = 0uL)

        // A player's loading thread is not the caller's.
        val read = async(Dispatchers.IO) {
            // From the start.
            assertFalse(source.isOpen)
            assertEquals(scene.bytes.size.toLong(), source.open(DataSpec()))
            assertTrue(source.isOpen)
            assertContentEquals(scene.slice(0, 150_000), source.readFully(150_000))
            source.close()
            assertFalse(source.isOpen)

            // A seek to the middle, over the end of one chunk and into the next.
            val middle = CHUNK * 3 - 150_000
            assertEquals(300_000L, source.open(DataSpec(middle.toLong(), 300_000)))
            assertContentEquals(scene.slice(middle, 300_000), source.readFully(400_000))
            assertEquals(RESULT_END_OF_INPUT, source.read(ByteArray(16), 0, 16))
            source.close()

            // The end of the blob, read until the source says it ended, and a
            // range that reaches past the end.
            val end = scene.bytes.size - 70_000
            assertEquals(70_000L, source.open(DataSpec(end.toLong())))
            assertContentEquals(scene.slice(end, 70_000), source.readFully(1_000_000))
            source.close()
            assertEquals(10L, source.open(DataSpec(scene.bytes.size - 10L, 4096)))
            assertContentEquals(scene.slice(scene.bytes.size - 10, 10), source.readFully(4096))
            source.close()
            assertEquals(0L, source.open(DataSpec(scene.bytes.size.toLong())))
            source.close()

            // A position outside the blob: the open fails, the source is not
            // open, and closing it, as a player does, ends its reader.
            assertFailsWith<java.io.IOException> { source.open(DataSpec(scene.bytes.size + 1L)) }
            assertFalse(source.isOpen)
            source.close()
            assertFailsWith<java.io.IOException> { source.open(DataSpec(-1L)) }
            source.close()
        }
        read.await()

        // The chunks that were read are in the cache, and the blob is not whole
        // here: the chunks between them were never fetched.
        val local = scene.blobs.local(scene.blob)
        assertEquals(BlobState.CACHED, local.state)
        assertTrue(local.bytes > 0uL && local.bytes < scene.size - CHUNK.toULong())
        assertTrue(scene.blobs.status(scene.blob) != BlobStatus.Readable)
        assertNull(scene.blobs.get(scene.blob, ReadOptions(local = true)))
        assertEquals(BlobCacheUsage(256uL shl 20, local.bytes, 0uL), scene.device.blobCacheUsage())

        // A reader by itself: it knows no size before its first read, says how
        // far what it gave was checked, and fails every read once it is ended.
        val reader = scene.blobs.openReader(scene.blob)
        reader.setReadAhead(0uL)
        assertEquals(0uL, reader.readAhead())
        assertNull(reader.size())
        assertContentEquals(scene.slice(CHUNK - 3, 6), reader.readAt((CHUNK - 3).toULong(), 6uL))
        assertEquals(scene.size, reader.size())
        assertEquals(Verified.CHUNKS, reader.verified())

        // A read is at most 64 MiB: one byte more is refused, and says so.
        assertContentEquals(scene.slice(scene.bytes.size - 4, 4), reader.readAt(scene.size - 4uL, 64uL shl 20))
        val refused = assertFailsWith<FrasilException> { reader.readAt(0uL, (64uL shl 20) + 1uL) }
        assertTrue(refused.message?.contains("at most 67108864 bytes") == true, refused.message)

        reader.end()
        assertFailsWith<FrasilException> { reader.readAt(0uL, 1uL) }
        reader.close()
        scene.close()
    }

    @Test fun anInterruptedLoadStopsAndTheNextReadsOn() = runBlocking {
        // A budget of zero: every read passes through memory.
        val scene = Scene.make(20, DeviceOptions(blobCache = 0uL, loopback = true))
        val source = BlobDataSource(scene.blobs, scene.blob, ReadOptions(uncached = true), piece = 64 * 1024, readAhead = 0uL)

        // A player loads the whole blob on a thread of its own, and cancels the
        // load by interrupting the thread. The thread waits, once its first
        // bytes arrived, until the interrupt is sent: the load is not at its
        // end then, and its next call on the device is the one interrupted.
        val started = CountDownLatch(1)
        val sent = CountDownLatch(1)
        val loaded = AtomicInteger()
        val ended = AtomicReference<Throwable?>()
        val loading = Thread {
            try {
                source.open(DataSpec())
                val buffer = ByteArray(8192)
                while (true) {
                    val read = source.read(buffer, 0, buffer.size)
                    if (read == RESULT_END_OF_INPUT) break
                    assertContentEquals(scene.slice(loaded.get(), read), buffer.copyOf(read))
                    loaded.addAndGet(read)
                    if (started.count == 1L) {
                        started.countDown()
                        // The interrupt may land here: it stays set for the
                        // source's next call to find.
                        try {
                            sent.await()
                        } catch (interrupted: InterruptedException) {
                            Thread.currentThread().interrupt()
                        }
                    }
                }
            } catch (thrown: Throwable) {
                ended.set(thrown)
            }
        }
        loading.start()
        assertTrue(started.await(30, TimeUnit.SECONDS))
        loading.interrupt()
        sent.countDown()
        loading.join(30_000)
        assertFalse(loading.isAlive)
        assertTrue(ended.get() is InterruptedIOException, "${ended.get()}")
        // What the source held when the interrupt came, at most one piece.
        assertTrue(loaded.get() <= 64 * 1024, "${loaded.get()}")
        // A player closes the source on the thread it interrupted, which the
        // interrupt has ended; here another thread does.
        source.close()

        // The source reads on: the load that was interrupted holds nothing.
        val after = async(Dispatchers.IO) {
            assertEquals(1000L, source.open(DataSpec((CHUNK * 2 + 5).toLong(), 1000)))
            val read = source.readFully(1000)
            source.close()
            read
        }
        assertContentEquals(scene.slice(CHUNK * 2 + 5, 1000), after.await())

        // A read given a cancellation that was cancelled before fails at once,
        // and its reader reads on.
        val reader = scene.blobs.openReader(scene.blob, ReadOptions(uncached = true))
        reader.setReadAhead(0uL)
        val cancelled = Cancellation()
        cancelled.cancel()
        assertTrue(cancelled.isCancelled())
        assertFailsWith<FrasilException> { reader.readAt(0uL, 10uL, cancelled) }
        cancelled.close()
        assertContentEquals(scene.slice(scene.bytes.size - 5, 5), reader.readAt(scene.size - 5uL, 100uL))

        // That a read which waits for a chunk ends when its coroutine is
        // cancelled, when its cancellation is cancelled, and when its reader
        // is ended, is tested in the crate (the three `a_waiting_read_ends_`
        // tests in crates/frasil-uniffi/src/reads.rs), where a read can be
        // held waiting; here a read may have ended before any reaches it.

        // Every reader ended: nothing of the blob stays on the device.
        reader.end()
        assertEquals(BlobState.ABSENT, scene.blobs.local(scene.blob).state)
        assertEquals(BlobCacheUsage(0uL, 0uL, 0uL), scene.device.blobCacheUsage())
        reader.close()
        scene.close()
    }

    @Test fun aDeviceKeepsAndDropsABlob() = runBlocking {
        val scene = Scene.make(30, DeviceOptions(blobCache = 64uL shl 20, loopback = true))
        // Nothing is fetched for a local read.
        assertNull(scene.blobs.getRange(scene.blob, 0uL, 10uL, ReadOptions(local = true)))
        assertNull(scene.blobs.contentHash(scene.blob, ReadOptions(local = true)))

        // A range read fetches the chunk it lies in, into the cache.
        assertContentEquals(scene.slice(CHUNK + 7, 9), scene.blobs.getRange(scene.blob, (CHUNK + 7).toULong(), 9uL))
        val part = scene.blobs.local(scene.blob)
        assertEquals(BlobState.CACHED, part.state)
        assertTrue(part.bytes > 0uL && part.bytes < scene.size)

        // Kept: fetched whole, and outside the cache's budget.
        scene.blobs.keep(scene.blob, null)
        val kept = scene.blobs.local(scene.blob)
        assertEquals(BlobState.KEPT, kept.state)
        assertTrue(kept.bytes > scene.size)
        assertEquals(BlobStatus.Readable, scene.blobs.status(scene.blob))
        assertEquals(BlobCacheUsage(64uL shl 20, 0uL, kept.bytes), scene.device.blobCacheUsage())
        assertContentEquals(scene.bytes, scene.blobs.get(scene.blob, ReadOptions(local = true)))

        // Dropped: absent again, and nothing of it is stored.
        scene.blobs.dropLocal(scene.blob)
        assertEquals(BlobLocal(BlobState.ABSENT, 0uL, scene.size), scene.blobs.local(scene.blob))
        assertNull(scene.blobs.get(scene.blob, ReadOptions(local = true)))
        assertEquals(0uL, scene.device.blobCacheUsage().kept)

        // Another device put the blob: no change of this device's waits.
        assertTrue(scene.blobs.isDurable(scene.blob))
        assertTrue(scene.blobs.pending().isEmpty())
        scene.close()
    }

    @Test fun aReadSaysWhatBecomesOfABlob() = runBlocking {
        val scene = Scene.make(40)
        // A read that stores nothing leaves the blob absent.
        assertContentEquals(scene.bytes, scene.blobs.get(scene.blob, ReadOptions(uncached = true)))
        eventually("nothing stays of a read that stores nothing") {
            scene.blobs.local(scene.blob).state.takeIf { it == BlobState.ABSENT }
        }
        assertEquals(32, scene.blobs.contentHash(scene.blob, ReadOptions(uncached = true))?.size)

        // A read that keeps: the blob stays, whole, outside the budget.
        val file = java.io.File.createTempFile("frasil-reads", null)
        scene.blobs.getToFile(scene.blob, file.path, null, ReadOptions(keep = true))
        assertContentEquals(scene.bytes, file.readBytes())
        file.delete()
        assertEquals(BlobState.KEPT, scene.blobs.local(scene.blob).state)
        assertEquals(BlobStatus.Readable, scene.blobs.status(scene.blob))

        // A reader over a blob that is whole here reads it from the device,
        // and every check has run on it.
        val reader = scene.blobs.openReader(scene.blob, ReadOptions(local = true))
        assertEquals(scene.size, reader.fetchSize())
        assertContentEquals(scene.slice(CHUNK - 3, 6), reader.readAt((CHUNK - 3).toULong(), 6uL))
        eventually("the whole blob was checked") { reader.verified().takeIf { it == Verified.WHOLE } }
        reader.end()
        reader.close()
        scene.close()
    }
}
