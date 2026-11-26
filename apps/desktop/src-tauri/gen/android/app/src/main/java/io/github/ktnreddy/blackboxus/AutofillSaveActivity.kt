package io.github.ktnreddy.blackboxus

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * Asks before saving a login typed into another app, after the person
 * chose "Save" in Android's prompt, as a sheet over that app. The Rust
 * side of the app does the saving, so BlackBoxus must be running and
 * unlocked; if it isn't, the person is sent to unlock it, brought back
 * here ([BackAfterUnlock]), and the save goes through.
 */
class AutofillSaveActivity : Activity() {
  private val worker = Executors.newSingleThreadExecutor()
  private val main = Handler(Looper.getMainLooper())
  private lateinit var name: EditText
  private lateinit var status: TextView
  private lateinit var save: Button
  private var busy = false
  private lateinit var unlock: BackAfterUnlock

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    val pending = PendingSave.get()
    if (pending == null) {
      finish()
      return
    }
    unlock = BackAfterUnlock(this, worker) { trySave() }
    Sheet.show(this)
    // Not closed by a stray tap above it: what was typed would be lost.
    setFinishOnTouchOutside(false)
    buildScreen(pending)
  }

  override fun onResume() {
    super.onResume()
    if (::unlock.isInitialized) unlock.checkNow()
  }

  override fun onDestroy() {
    if (::unlock.isInitialized) unlock.stop()
    worker.shutdownNow()
    super.onDestroy()
  }

  private fun dp(value: Int): Int =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

  private fun text(size: Float, color: Int, value: String = ""): TextView = TextView(this).apply {
    setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
    setTextColor(color)
    text = value
  }

  private fun rounded(color: Int) = GradientDrawable().apply {
    setColor(color)
    cornerRadius = dp(14).toFloat()
  }

  private fun full(top: Int = 0) =
    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
      topMargin = dp(top)
    }

  private fun buildScreen(pending: PendingSave) {
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(20), dp(12), dp(20), dp(20))
    }
    root.addView(Sheet.handle(this), LinearLayout.LayoutParams(dp(36), dp(4)).apply {
      gravity = android.view.Gravity.CENTER_HORIZONTAL
      bottomMargin = dp(12)
    })
    root.addView(
      text(24f, TEXT, getString(R.string.save_title)).apply {
        typeface = Typeface.create("sans-serif-light", Typeface.NORMAL)
      },
    )
    val where = if (pending.page != null) {
      getString(R.string.save_for_site, pending.page.substringAfter("://"))
    } else {
      getString(R.string.save_for_app, pending.title)
    }
    root.addView(text(15f, SOFT, where), full(6))

    root.addView(text(13f, SOFT, getString(R.string.save_name)), full(20))
    name = EditText(this).apply {
      setText(pending.title)
      setTextColor(TEXT)
      isSingleLine = true
      inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
      importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
      background = rounded(PANEL)
      setPadding(dp(14), dp(12), dp(14), dp(12))
    }
    root.addView(name, full(6))

    if (pending.username.isNotEmpty()) {
      root.addView(text(13f, SOFT, getString(R.string.save_username)), full(14))
      root.addView(
        text(16f, TEXT, pending.username).apply {
          background = rounded(PANEL)
          setPadding(dp(14), dp(12), dp(14), dp(12))
        },
        full(6),
      )
    }
    root.addView(
      text(13f, SOFT, getString(R.string.save_password, pending.password.size)),
      full(14),
    )
    root.addView(text(13f, MUTED, getString(R.string.save_explain)), full(14))

    status = text(14f, WARN).apply {
      visibility = View.GONE
      background = rounded(WARN_BG)
      setPadding(dp(12), dp(10), dp(12), dp(10))
    }
    root.addView(status, full(16))

    save = Button(this).apply {
      text = getString(R.string.save_button)
      isAllCaps = false
      setTextColor(Color.BLACK)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
      background = rounded(ACCENT)
      setOnClickListener { trySave() }
    }
    root.addView(save, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)).apply { topMargin = dp(16) })
    root.addView(
      Button(this).apply {
        text = getString(R.string.save_not_now)
        isAllCaps = false
        setTextColor(SOFT)
        setBackgroundColor(Color.TRANSPARENT)
        setOnClickListener {
          PendingSave.clear()
          finish()
        }
      },
      LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)).apply { topMargin = dp(6) },
    )
    setContentView(Sheet.wrap(this, root))
  }

  private fun say(message: String, color: Int = WARN) {
    status.text = message
    status.setTextColor(color)
    status.visibility = View.VISIBLE
  }

  /** Hands the login to the app to save. */
  private fun trySave() {
    if (busy) return
    val pending = PendingSave.get()
    if (pending == null) {
      say(getString(R.string.save_expired))
      save.isEnabled = false
      return
    }
    if (!AutofillBroker.connected()) {
      locked()
      return
    }
    busy = true
    save.isEnabled = false
    save.text = getString(R.string.save_saving)
    save.setOnClickListener { trySave() }
    val question = JSONObject()
      .put("kind", "save")
      .put("title", name.text.toString().trim().ifEmpty { pending.title })
      .put("username", pending.username)
      .put("password", String(pending.password))
      .put("page", pending.page ?: JSONObject.NULL)
    worker.execute {
      val answer = AutofillBroker.ask(question, TIMEOUT_MS)
      main.post {
        busy = false
        save.isEnabled = true
        save.text = getString(R.string.save_button)
        if (isFinishing) return@post
        saved(answer)
      }
    }
  }

  private fun saved(answer: JSONObject?) {
    when {
      answer == null || answer.optString("error") == "locked" -> locked()
      answer.has("error") -> say(
        getString(R.string.save_failed, answer.optString("message", answer.optString("error"))),
      )
      else -> {
        PendingSave.clear()
        val vault = answer.optString("vault_name", "BlackBoxus")
        val done = if (answer.optBoolean("updated")) R.string.save_updated else R.string.save_saved
        say(getString(done, vault), OK)
        save.isEnabled = false
        main.postDelayed({ if (!isFinishing) finish() }, 1200)
      }
    }
  }

  /** The app is closed or locked: send the person to unlock it. */
  private fun locked() {
    say(getString(if (unlock.waiting) R.string.autofill_waiting else R.string.save_locked))
    save.text = getString(R.string.autofill_open)
    save.isEnabled = true
    save.setOnClickListener { unlock.unlock() }
  }

  private companion object {
    /** Saving talks to the server, so it may take a while. */
    const val TIMEOUT_MS = 30_000L
    val PANEL = Color.rgb(24, 24, 27)
    val TEXT = Color.rgb(244, 244, 245)
    val SOFT = Color.rgb(161, 161, 170)
    val MUTED = Color.rgb(113, 113, 122)
    val ACCENT = Color.rgb(255, 106, 26)
    val WARN = Color.rgb(253, 186, 116)
    val OK = Color.rgb(134, 239, 172)
    val WARN_BG = Color.argb(36, 255, 106, 26)
  }
}
