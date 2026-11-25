import frasil.AdmissionListener
import frasil.Cancellation
import frasil.Device
import frasil.DeviceOptions
import frasil.FrasilException
import frasil.Space
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Whether a failure's message has [part] in it. */
private fun Throwable?.says(part: String) = this?.message?.contains(part) == true

/**
 * A listener that notes what it is shown, then answers [answer], or throws
 * for none; when [held] it waits until it is released first.
 */
private class Asks(private val answer: Boolean?, held: Boolean = false) : AdmissionListener {
    private val gate = CountDownLatch(if (held) 1 else 0)
    private val asked = CountDownLatch(1)
    private val back = CountDownLatch(1)
    private val seen = AtomicReference<Pair<String, String>?>()

    override fun confirm(code: String, name: String): Boolean {
        seen.set(code to name)
        asked.countDown()
        gate.await()
        back.countDown()
        return answer ?: throw IllegalStateException("the screen is gone")
    }

    /** Lets a held listener answer. */
    fun release() = gate.countDown()

    /** The code and the name the listener was shown, if it was asked. */
    val shown get() = seen.get()

    /** Whether the listener gave its answer. */
    val returned get() = back.count == 0L

    /** Waits until the listener is asked. */
    fun awaitAsked() = assertTrue(asked.await(30, TimeUnit.SECONDS), "the listener is asked")

    /** Waits until the listener gave its answer. */
    fun awaitReturned() = assertTrue(back.await(30, TimeUnit.SECONDS), "the listener returns")
}

/**
 * A device that administers a space, and one that is to join it, both on
 * loopback with no peer.
 */
private class Devices(val host: Device, val newcomer: Device, val space: Space) {
    /** Whether the space names the newcomer a member, as the host has it. */
    suspend fun admitted() = space.members().any { it.id == newcomer.id() }

    suspend fun close() {
        newcomer.shutdown()
        host.shutdown()
        newcomer.close()
        host.close()
    }

    companion object {
        suspend fun make(key: Int): Devices {
            val host = Device.openInMemory(ByteArray(32) { key.toByte() }, DeviceOptions(loopback = true))
            val newcomer = Device.openInMemory(ByteArray(32) { (key + 1).toByte() }, DeviceOptions(loopback = true))
            return Devices(host, newcomer, host.createSpace())
        }
    }
}

class AdmissionTest {
    @Test fun aNewcomerJoinsOnceBothConfirmOneCode() = runBlocking {
        val devices = Devices.make(110)
        val hosts = Asks(true)
        val joins = Asks(true)
        val invitation = devices.space.invite("write", "host", hosts)
        val joined = devices.newcomer.join(invitation.text(), "newcomer", joins)
        invitation.admitted()

        // Both listeners were shown one code of six digits, each with the
        // name the other device gave.
        val host = assertNotNull(hosts.shown)
        val newcomer = assertNotNull(joins.shown)
        assertEquals(host.first, newcomer.first)
        assertTrue(host.first.length == 6 && host.first.all { it.isDigit() })
        assertEquals("newcomer", host.second)
        assertEquals("host", newcomer.second)

        assertEquals(devices.space.id(), joined.id())
        assertEquals("write", devices.space.members().single { it.id == devices.newcomer.id() }.level)

        // The invitation admitted its newcomer: it is spent, and says so.
        val spent = assertFailsWith<FrasilException> { invitation.admitted() }
        assertTrue(spent.says("the invitation is spent") && spent.says("invite again"))
        devices.close()
    }

    @Test fun aNearbyAdmissionMakesNoAdministrator() = runBlocking {
        val devices = Devices.make(120)
        val refused = assertFailsWith<FrasilException> { devices.space.invite("administer", "host", Asks(true)) }
        assertTrue(refused.says("read or write") && refused.says("raise"))
        devices.close()
    }

    @Test fun theInvitersNoRefusesTheNewcomer() = runBlocking {
        val devices = Devices.make(130)
        val hosts = Asks(false)
        val joins = Asks(true)
        val invitation = devices.space.invite("write", "host", hosts)
        assertFailsWith<FrasilException> { devices.newcomer.join(invitation.text(), "newcomer", joins) }
        assertFailsWith<FrasilException> { invitation.admitted() }
        assertEquals(assertNotNull(hosts.shown).first, joins.shown?.first)
        assertFalse(devices.admitted())
        assertTrue(devices.newcomer.spaces().isEmpty())
        devices.close()
    }

    @Test fun theNewcomersNoRefusesIt() = runBlocking {
        val devices = Devices.make(140)
        // The newcomer's person answers once both listeners are asked.
        val hosts = Asks(true)
        val joins = Asks(false, held = true)
        val invitation = devices.space.invite("write", "host", hosts)
        val joining = async(Dispatchers.Default) {
            runCatching { devices.newcomer.join(invitation.text(), "newcomer", joins) }
        }
        hosts.awaitAsked()
        joins.awaitAsked()
        assertEquals(assertNotNull(hosts.shown).first, joins.shown?.first)
        joins.release()
        assertTrue(withTimeout(30_000) { joining.await() }.exceptionOrNull() is FrasilException)
        assertTrue(devices.newcomer.spaces().isEmpty())
        devices.close()
    }

    @Test fun aListenerThatThrowsRefuses() = runBlocking {
        // The inviter's listener throws: the newcomer is no member.
        val devices = Devices.make(150)
        val invitation = devices.space.invite("write", "host", Asks(null))
        assertFailsWith<FrasilException> { devices.newcomer.join(invitation.text(), "newcomer", Asks(true)) }
        assertFailsWith<FrasilException> { invitation.admitted() }
        assertFalse(devices.admitted())
        devices.close()

        // The newcomer's listener throws: it joins nothing.
        val other = Devices.make(160)
        val second = other.space.invite("write", "host", Asks(true))
        assertFailsWith<FrasilException> { other.newcomer.join(second.text(), "newcomer", Asks(null)) }
        assertTrue(other.newcomer.spaces().isEmpty())
        other.close()
    }

    @Test fun aCancelledWaitAbandonsItsInvitation() = runBlocking {
        val devices = Devices.make(170)
        // The inviter's person never answers.
        val hosts = Asks(true, held = true)
        val invitation = devices.space.invite("write", "host", hosts)
        val began = AtomicBoolean()
        val waiting = async(Dispatchers.Default, CoroutineStart.UNDISPATCHED) {
            began.set(true)
            invitation.admitted()
        }
        assertTrue(began.get())
        val joining = async(Dispatchers.Default) {
            runCatching { devices.newcomer.join(invitation.text(), "newcomer", Asks(true)) }
        }
        hosts.awaitAsked()

        // The coroutine is cancelled while the listener is asked: the wait
        // ends, and the newcomer is refused without the listener's answer.
        withTimeout(30_000) { waiting.cancelAndJoin() }
        assertTrue(waiting.isCancelled)
        val refused = withTimeout(30_000) { joining.await() }
        assertTrue(refused.exceptionOrNull() is FrasilException, "$refused")
        assertFalse(hosts.returned)
        assertFalse(devices.admitted())
        assertTrue(devices.newcomer.spaces().isEmpty())

        // The invitation is spent, and says why.
        val spent = assertFailsWith<FrasilException> { invitation.admitted() }
        assertTrue(spent.says("the invitation is spent") && spent.says("was cancelled"))

        // The listener's late answer counts for nothing.
        hosts.release()
        hosts.awaitReturned()
        assertFalse(devices.admitted())
        devices.close()
    }

    @Test fun aCancellationAbandonsAnInvitation() = runBlocking {
        val devices = Devices.make(180)
        val hosts = Asks(true, held = true)
        val invitation = devices.space.invite("write", "host", hosts)
        val cancellation = Cancellation()
        val waiting = async(Dispatchers.Default) { runCatching { invitation.admitted(cancellation) } }
        val joining = async(Dispatchers.Default) {
            runCatching { devices.newcomer.join(invitation.text(), "newcomer", Asks(true)) }
        }
        hosts.awaitAsked()
        cancellation.cancel()
        val cancelled = withTimeout(30_000) { waiting.await() }.exceptionOrNull()
        assertTrue(cancelled is FrasilException && cancelled.says("the admission was cancelled"), "$cancelled")
        assertTrue(withTimeout(30_000) { joining.await() }.exceptionOrNull() is FrasilException)
        assertFalse(devices.admitted())
        hosts.release()
        hosts.awaitReturned()
        cancellation.close()
        devices.close()
    }

    @Test fun aCancelledJoinJoinsNothing() = runBlocking {
        val devices = Devices.make(190)
        // The inviter's person does not confirm: a device that confirmed has
        // granted, whatever the newcomer does after.
        val invitation = devices.space.invite("write", "host", Asks(false))

        // The newcomer's person never answers, and the coroutine that joins
        // is cancelled.
        val joins = Asks(true, held = true)
        val joining = async(Dispatchers.Default) { devices.newcomer.join(invitation.text(), "newcomer", joins) }
        joins.awaitAsked()
        withTimeout(30_000) { joining.cancelAndJoin() }
        assertTrue(joining.isCancelled)
        assertFalse(joins.returned)
        joins.release()
        joins.awaitReturned()
        assertTrue(devices.newcomer.spaces().isEmpty())

        // The same by a cancellation, which the call reports.
        val second = devices.space.invite("write", "host", Asks(false))
        val held = Asks(true, held = true)
        val cancellation = Cancellation()
        val cancelling = async(Dispatchers.Default) {
            runCatching { devices.newcomer.join(second.text(), "newcomer", held, cancellation) }
        }
        held.awaitAsked()
        cancellation.cancel()
        val cancelled = withTimeout(30_000) { cancelling.await() }.exceptionOrNull()
        assertTrue(cancelled is FrasilException && cancelled.says("the admission was cancelled"), "$cancelled")
        held.release()
        held.awaitReturned()
        assertTrue(devices.newcomer.spaces().isEmpty())
        cancellation.close()

        // The device joins by a new invitation.
        val again = devices.space.invite("read", "host", Asks(true))
        val joined = devices.newcomer.join(again.text(), "newcomer", Asks(true))
        again.admitted()
        assertEquals(devices.space.id(), joined.id())
        assertEquals("read", devices.space.members().single { it.id == devices.newcomer.id() }.level)
        devices.close()
    }
}
