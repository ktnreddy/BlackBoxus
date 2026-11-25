package io.github.ktnreddy.blackboxus

import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Carries the autofill picker's questions to the Rust side of the app, which
 * holds the unlocked vaults, and brings the answers back.
 *
 * Rust asks for the next question through [AutofillPlugin] and waits; the
 * picker hands a question over with [ask]. Nothing here keeps vault data:
 * an answer goes straight to the picker that asked for it.
 */
object AutofillBroker {
  /** Takes the next question to Rust. */
  fun interface Waiter {
    fun deliver(question: JSONObject)
  }

  private val lock = Any()
  private var waiter: Waiter? = null
  private val queue = ArrayDeque<JSONObject>()
  private val answers = ConcurrentHashMap<Long, CompletableFuture<JSONObject>>()
  private val ids = AtomicLong()

  @Volatile
  private var connected = false

  /**
   * Whether the Rust side has asked for questions in this process, so the
   * app is running. When it isn't, nobody will answer.
   */
  fun connected(): Boolean = connected

  /** Rust is ready for the next question. */
  fun waitForQuestion(next: Waiter) {
    connected = true
    val question: JSONObject?
    synchronized(lock) {
      question = queue.removeFirstOrNull()
      if (question == null) waiter = next
    }
    if (question != null) next.deliver(question)
  }

  /** Rust's answer to question [id]. */
  fun answer(id: Long, body: String) {
    val parsed = try {
      JSONObject(body)
    } catch (e: org.json.JSONException) {
      JSONObject().put("error", "malformed")
    }
    answers.remove(id)?.complete(parsed)
  }

  /**
   * Asks Rust and waits for the answer. Returns null if no answer comes in
   * time, which means the app is not running. Never call on the main thread.
   */
  fun ask(question: JSONObject, timeoutMs: Long): JSONObject? {
    val id = ids.incrementAndGet()
    question.put("id", id)
    val future = CompletableFuture<JSONObject>()
    answers[id] = future
    val ready: Waiter?
    synchronized(lock) {
      ready = waiter
      waiter = null
      if (ready == null) queue.addLast(question)
    }
    ready?.deliver(question)
    return try {
      future.get(timeoutMs, TimeUnit.MILLISECONDS)
    } catch (e: Exception) {
      null
    } finally {
      answers.remove(id)
      synchronized(lock) { queue.remove(question) }
    }
  }
}
