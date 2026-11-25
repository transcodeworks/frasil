import frasil.BlobReader
import frasil.Blobs
import frasil.ReadOptions
import java.io.IOException
import java.io.InterruptedIOException
import kotlinx.coroutines.runBlocking

// A sample to copy into an application, not part of the library: it backs a
// Media3 player with a blob, so that the player plays a blob the device does
// not hold whole and fetches only what it reads.
//
// Media3 is an Android library: its `DataSource` names `android.net.Uri`, and
// this library's tests run on a plain JVM. `DataSource` and `DataSpec` below
// are the part of `androidx.media3.datasource.DataSource` and
// `androidx.media3.datasource.DataSpec` the adapter uses, with Media3's
// contract. In an application, delete the two, import Media3's, extend
// `BaseDataSource(/* isNetwork = */ true)`, and do as Media3's own sources
// do (`FileDataSource`, `ByteArrayDataSource`):
//
//     override fun getUri(): Uri? = uri            // the DataSpec's, kept by open()
//     // in open(), first: transferInitializing(dataSpec)
//     // in open(), for a position outside the blob:
//     //     throw DataSourceException(PlaybackException.ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE)
//     // in open(), last: opened = true; transferStarted(dataSpec)
//     // in read(), after copying: bytesTransferred(count)
//     // in close(): if (opened) { opened = false; transferEnded() }
//
// `transferEnded()` is called only for a source that `open()` opened: a
// player closes a source whose `open()` threw, and one it never opened. The
// `opened` flag below is that guard.
//
// Then give the player a `DataSource.Factory { BlobDataSource(blobs, blob) }`.
//
// One reader for each `open`. A player loads through several sources at a
// time, and opens a source again at each seek. A reader serves one call at a
// time and fetches ahead of the place it last read, so loads that share one
// take turns, each waits for the other's fetch, and each jump between them
// drops what the reader had asked for ahead. With a reader of its own, a load
// reads in order from its position, the reader fetches ahead of it, and
// `close()` ends the reader and its fetches. A reader costs nothing until it
// is read, and what one load fetched is in the device's cache for the next,
// unless the readers store nothing (`uncached`).

/** The length of a `DataSpec` that reads to the end, as Media3's `C.LENGTH_UNSET`. */
const val LENGTH_UNSET = -1L

/** What `read` returns at the end, as Media3's `C.RESULT_END_OF_INPUT`. */
const val RESULT_END_OF_INPUT = -1

/** Where a read starts and how much it reads, as Media3's `DataSpec`. */
data class DataSpec(val position: Long = 0, val length: Long = LENGTH_UNSET)

/** A source of bytes a player opens, reads and closes, as Media3's `DataSource`. */
interface DataSource {
    /** Opens the source at `dataSpec`; the bytes that can be read from there. */
    @Throws(IOException::class)
    fun open(dataSpec: DataSpec): Long

    /** Reads up to `length` bytes into `buffer` at `offset`; how many, or `RESULT_END_OF_INPUT`. */
    @Throws(IOException::class)
    fun read(buffer: ByteArray, offset: Int, length: Int): Int

    /** Closes the source: it can be opened again. */
    @Throws(IOException::class)
    fun close()
}

/**
 * Reads [blob] of [blobs] for a player, through a reader it opens at each
 * `open` with [read] and ends at `close`. A player calls a source from a
 * loading thread of its own and cancels a load by interrupting that thread:
 * each call here waits for the reader on the calling thread, and an interrupt
 * ends the call it waits for, in the device too.
 *
 * It asks the reader for [piece] bytes at a time and serves the player's
 * smaller reads from them. The reader fetches [readAhead] chunks ahead, or as
 * a reader does by itself with none.
 */
class BlobDataSource(
    private val blobs: Blobs,
    private val blob: String,
    private val read: ReadOptions? = null,
    private val piece: Int = 256 * 1024,
    private val readAhead: ULong? = null,
) : DataSource {
    private var reader: BlobReader? = null
    private var opened = false
    private var position = 0L
    private var remaining = 0L
    private var held = ByteArray(0)
    private var taken = 0

    override fun open(dataSpec: DataSpec): Long {
        // A source that was not closed since its last open.
        if (reader != null) close()
        if (dataSpec.position < 0) throw outside(dataSpec.position, null)
        val reader = waiting { blobs.openReader(blob, read) }
        this.reader = reader
        readAhead?.let { reader.setReadAhead(it) }
        // The first piece, read before the size is asked for: the read opens
        // the chunk the load starts in, and the size comes with it.
        val wanted = if (dataSpec.length == LENGTH_UNSET) piece.toLong() else minOf(piece.toLong(), dataSpec.length)
        val first = if (wanted > 0) waiting { reader.readAt(dataSpec.position.toULong(), wanted.toULong()) } else ByteArray(0)
        val size = (reader.size() ?: waiting { reader.fetchSize() }).toLong()
        // In Media3: DataSourceException(PlaybackException.ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE).
        if (dataSpec.position > size) throw outside(dataSpec.position, size)
        position = dataSpec.position
        remaining = when (dataSpec.length) {
            LENGTH_UNSET -> size - position
            else -> minOf(dataSpec.length, size - position)
        }
        held = first
        taken = 0
        opened = true
        return remaining
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (remaining == 0L) return RESULT_END_OF_INPUT
        if (taken == held.size) {
            val reader = reader ?: throw IOException("the source is not open")
            val want = minOf(piece.toLong(), remaining)
            // Fewer bytes than asked are what a read had before a chunk that
            // failed: the next read reports the failure.
            held = waiting { reader.readAt(position.toULong(), want.toULong()) }
            taken = 0
            // The blob ended before the size its header gave: nothing more.
            if (held.isEmpty()) return RESULT_END_OF_INPUT
        }
        val count = minOf(length.toLong(), (held.size - taken).toLong(), remaining).toInt()
        held.copyInto(buffer, offset, taken, taken + count)
        taken += count
        position += count
        remaining -= count
        return count
    }

    override fun close() {
        remaining = 0
        held = ByteArray(0)
        taken = 0
        // In Media3, here: transferEnded(), for a source that was opened.
        opened = false
        val ended = reader ?: return
        reader = null
        try {
            waiting { ended.end() }
        } finally {
            // Frees the handle: a reader whose `end` was interrupted ends
            // with it, once no call holds it.
            ended.close()
        }
    }

    /** Whether `open` opened the source and `close` has not closed it. */
    val isOpen get() = opened

    private fun outside(position: Long, size: Long?) =
        IOException("position $position is outside the blob" + (size?.let { " of $it bytes" } ?: ""))

    /** Waits for a call on the device; an interrupt of this thread ends the call. */
    private fun <T> waiting(call: suspend () -> T): T =
        try {
            runBlocking { call() }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw InterruptedIOException("the read was interrupted")
        } catch (failed: frasil.FrasilException) {
            throw IOException(failed.message, failed)
        }
}
