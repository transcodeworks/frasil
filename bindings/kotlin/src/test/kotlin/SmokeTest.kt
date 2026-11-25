import frasil.Arrival
import frasil.ArrivalListener
import frasil.BlobLocal
import frasil.BlobState
import frasil.BlobStatus
import frasil.BlobStatusListener
import frasil.CheckpointListener
import frasil.CheckpointPolicy
import frasil.CheckpointReport
import frasil.Device
import frasil.DeviceOptions
import frasil.DurableListener
import frasil.FrasilException
import frasil.ReadOptions
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Waits up to ten seconds until something heard passes [check]. */
private suspend fun <T> CopyOnWriteArrayList<T>.until(check: (T) -> Boolean): T {
    repeat(200) {
        firstOrNull(check)?.let { return it }
        delay(50)
    }
    error("nothing heard in time: $this")
}

class SmokeTest {
    @Test fun aDeviceHoldsASpaceAndItsBlobs() = runBlocking {
        val device = Device.openInMemory(ByteArray(32) { 1 }, DeviceOptions(blobCache = 1uL shl 20))
        val arrived = CopyOnWriteArrayList<Arrival>()
        val arrivals = device.arrivals(object : ArrivalListener {
            override fun arrived(arrival: Arrival) { arrived.add(arrival) }
        })
        val space = device.createSpace()
        assertEquals(listOf(space.id()), device.spaces())
        arrived.until { it == Arrival.Space(space.id()) }

        // No peer: the space has something unsent.
        val heard = CopyOnWriteArrayList<Boolean>()
        val following = space.observeDurable(object : DurableListener {
            override fun durable(durable: Boolean) { heard.add(durable) }
            override fun failed(message: String) {}
        })
        assertFalse(heard.until { true })
        assertFalse(space.isDurable())

        val blobs = space.createBlobs()
        val bytes = "hello from Kotlin".toByteArray()
        val blob = blobs.put("hello.txt", bytes)
        assertContentEquals(bytes, blobs.get(blob))
        assertEquals(BlobStatus.Readable, blobs.status(blob))
        val file = java.io.File.createTempFile("frasil", ".txt")
        file.writeBytes(bytes)
        val fromFile = blobs.putFile("file.txt", file.path, null)
        assertContentEquals(bytes, blobs.get(fromFile))
        file.delete()
        val statuses = CopyOnWriteArrayList<BlobStatus>()
        val watching = blobs.observeStatus(blob, object : BlobStatusListener {
            override fun status(status: BlobStatus) { statuses.add(status) }
            override fun failed(message: String) {}
        })
        assertEquals(BlobStatus.Readable, statuses.until { true })
        assertEquals(32, blobs.contentHash(blob)?.size)
        assertContentEquals("from".toByteArray(), blobs.getRange(blob, 6uL, 4uL))
        val read = java.io.File.createTempFile("frasil-get-to-file", null)
        blobs.getToFile(blob, read.path, null)
        assertContentEquals(bytes, read.readBytes())
        read.delete()
        arrived.until { it == Arrival.Stream(space.id(), blobs.id()) }

        // A blob this device put, in a space with no peer: kept, outside the
        // cache's budget, and its change waits for an acknowledgement.
        val local = blobs.local(blob)
        assertEquals(BlobState.KEPT, local.state)
        assertEquals(bytes.size.toULong(), local.size)
        assertTrue(local.bytes > local.size)
        val usage = device.blobCacheUsage()
        assertEquals(1uL shl 20, usage.budget)
        assertEquals(0uL, usage.cached)
        assertTrue(usage.kept >= local.bytes)
        assertFalse(blobs.isDurable(blob))
        assertEquals(listOf(blob, fromFile).sorted(), blobs.pending().sorted())
        blobs.keep(blob, null)
        assertContentEquals(bytes, blobs.get(blob, ReadOptions(local = true)))

        // A reader over it reads any range, and every check has run on a blob
        // that is whole here.
        val reader = blobs.openReader(blob)
        assertEquals(bytes.size.toULong(), reader.fetchSize())
        assertContentEquals("from".toByteArray(), reader.readAt(6uL, 4uL))
        assertContentEquals("Kotlin".toByteArray(), reader.readAt(11uL, 100uL))
        assertEquals(0, reader.readAt(100uL, 1uL).size)
        assertEquals(bytes.size.toULong(), reader.size())
        assertEquals(8uL, reader.readAhead())
        reader.setReadAhead(1000uL)
        assertEquals(64uL, reader.readAhead())
        assertEquals(0uL, reader.windowBytes())
        reader.end()
        reader.close()

        // Dropped, with nothing connected that could send it again: missing.
        blobs.dropLocal(blob)
        assertEquals(BlobLocal(BlobState.ABSENT, 0uL, local.size), blobs.local(blob))
        assertEquals(BlobStatus.Missing, blobs.status(blob))
        assertNull(blobs.get(blob))

        space.pauseSync()
        assertTrue(space.isSyncPaused())
        device.resumeSync(listOf(space.id()))
        assertFalse(space.isSyncPaused())

        listOf(arrivals, following, watching).forEach { it.cancel() }
        device.shutdown()
        device.close()
    }

    @Test fun anAdministratorProposesACheckpointAndFollowsIt() = runBlocking {
        val device = Device.openInMemory(ByteArray(32) { 2 })
        device.setCheckpointPolicy(CheckpointPolicy(propose = false))
        assertEquals(
            CheckpointPolicy(propose = false, forget = true, rosterEvents = 1024uL, frameBytes = 4_194_304uL),
            device.checkpointPolicy(),
        )
        val reports = CopyOnWriteArrayList<CheckpointReport>()
        val following = device.checkpointReports(object : CheckpointListener {
            override fun reported(report: CheckpointReport) { reports.add(report) }
        })
        val space = device.createSpace()
        // The space's creator holds the top rank.
        assertEquals(255.toUByte(), space.myRank())
        val members = space.members()
        assertEquals(1, members.size)
        assertEquals("administer", members[0].level)
        assertEquals(255.toUByte(), members[0].rank)
        assertTrue(space.recoveryMembers().isEmpty())
        val before = space.checkpoints()
        assertNull(before.inEffect)
        assertTrue(before.pending.isEmpty())

        // Alone in the space, its administrator votes by the checkpoint itself.
        val checkpoint = space.proposeCheckpoint()
        assertEquals(checkpoint, space.checkpoints().following)
        assertTrue(space.lateChanges().isEmpty())

        // A device of no person has no device list to checkpoint.
        val list = device.listCheckpoints()
        assertNull(list.inEffect)
        assertTrue(list.pending.isEmpty())
        assertFailsWith<FrasilException> { device.proposeListCheckpoint() }

        following.cancel()
        device.shutdown()
        device.close()
    }

    @Test fun aWrongUnlockKeyIsAnError() = runBlocking {
        assertFailsWith<FrasilException> { Device.openInMemory(ByteArray(0)) }
        Unit
    }
}
