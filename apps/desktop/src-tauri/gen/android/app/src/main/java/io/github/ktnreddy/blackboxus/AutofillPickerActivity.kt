package io.github.ktnreddy.blackboxus

import android.app.Activity
import android.app.assist.AssistStructure
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.Dataset
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.RemoteViews
import android.widget.TextView
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * Fills a login into another app.
 *
 * Opened with a login ([EXTRA_VAULT], [EXTRA_ITEM]) when the person tapped
 * it under the field: it fills straight away, without showing a list.
 * Opened without one ("Fill with BlackBoxus"), it lists logins to choose
 * from, as a sheet over the app. In a browser, only logins for the page's
 * site are listed; in other apps the person searches for the login.
 *
 * Logins come from the Rust side of the app, which must be running and
 * unlocked. If it isn't, the person is sent to unlock it and brought back
 * here once they have ([BackAfterUnlock]).
 */
class AutofillPickerActivity : Activity() {
  private val worker = Executors.newSingleThreadExecutor()
  private val main = Handler(Looper.getMainLooper())
  private lateinit var form: SignInForm
  private lateinit var list: LinearLayout
  private lateinit var status: TextView
  private var logins: List<JSONObject> = emptyList()
  private var busy = false
  private lateinit var unlock: BackAfterUnlock
  /** The login tapped under the field, to fill without showing a list. */
  private var direct: JSONObject? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Keeps the list out of screenshots and the recent-apps preview.
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    setResult(RESULT_CANCELED)
    val structure = structureOf(intent)
    if (structure == null) {
      finish()
      return
    }
    form = AutofillFields.find(structure)
    unlock = BackAfterUnlock(this, worker) { start() }
    val vault = intent.getStringExtra(EXTRA_VAULT)
    val item = intent.getStringExtra(EXTRA_ITEM)
    if (vault != null && item != null) {
      direct = JSONObject().put("vault", vault).put("item", item)
    }
    Sheet.show(this)
    buildScreen()
    start()
  }

  override fun onResume() {
    super.onResume()
    unlock.checkNow()
  }

  override fun onDestroy() {
    unlock.stop()
    worker.shutdownNow()
    super.onDestroy()
  }

  /** Fills the tapped login, or lists logins to choose from. */
  private fun start() {
    val login = direct
    if (login != null) {
      status.text = getString(R.string.autofill_filling)
      status.visibility = View.VISIBLE
      list.removeAllViews()
      fill(login)
    } else {
      load()
    }
  }

  @Suppress("DEPRECATION")
  private fun structureOf(intent: Intent): AssistStructure? =
    if (Build.VERSION.SDK_INT >= 33) {
      intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
    } else {
      intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
    }

  private fun dp(value: Int): Int =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

  private fun text(size: Float, color: Int, value: String = ""): TextView = TextView(this).apply {
    setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
    setTextColor(color)
    text = value
  }

  private fun buildScreen() {
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(20), dp(12), dp(20), dp(20))
    }
    root.addView(Sheet.handle(this), LinearLayout.LayoutParams(dp(36), dp(4)).apply {
      gravity = Gravity.CENTER_HORIZONTAL
      bottomMargin = dp(12)
    })
    val header = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
    }
    header.addView(
      text(22f, TEXT, getString(R.string.autofill_title)).apply { typeface = Typeface.create("sans-serif-light", Typeface.NORMAL) },
      LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
    )
    header.addView(
      Button(this).apply {
        text = getString(R.string.autofill_cancel)
        setTextColor(ACCENT)
        setBackgroundColor(Color.TRANSPARENT)
        isAllCaps = false
        setOnClickListener { finish() }
      },
    )
    root.addView(header)

    val where = if (form.page != null) {
      getString(R.string.autofill_for_site, form.page!!.substringAfter("://"))
    } else {
      getString(R.string.autofill_for_app, form.packageName)
    }
    root.addView(text(14f, SOFT, where).apply { setPadding(0, dp(4), 0, dp(12)) })

    if (form.page == null) {
      root.addView(
        text(13f, WARN, getString(R.string.autofill_app_warning)).apply {
          background = rounded(WARN_BG)
          setPadding(dp(12), dp(10), dp(12), dp(10))
        },
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
          bottomMargin = dp(12)
        },
      )
      root.addView(
        EditText(this).apply {
          hint = getString(R.string.autofill_search)
          setHintTextColor(MUTED)
          setTextColor(TEXT)
          isSingleLine = true
          inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
          // The search box itself is never offered for autofill.
          importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
          background = rounded(PANEL)
          setPadding(dp(14), dp(12), dp(14), dp(12))
          addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = show(s?.toString().orEmpty())
          })
        },
        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
          bottomMargin = dp(8)
        },
      )
    }

    status = text(14f, SOFT, getString(R.string.autofill_loading)).apply { setPadding(0, dp(12), 0, dp(12)) }
    root.addView(status)
    list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    root.addView(list)
    setContentView(Sheet.wrap(this, root))
  }

  private fun rounded(color: Int) = GradientDrawable().apply {
    setColor(color)
    cornerRadius = dp(14).toFloat()
  }

  /** Asks the app for the logins to list. */
  private fun load() {
    if (!AutofillBroker.connected()) {
      locked()
      return
    }
    status.text = getString(R.string.autofill_loading)
    status.visibility = View.VISIBLE
    val question = JSONObject().put("kind", "logins").put("page", form.page ?: JSONObject.NULL)
    worker.execute {
      val answer = AutofillBroker.ask(question, TIMEOUT_MS)
      main.post { if (!isFinishing) listed(answer) }
    }
  }

  private fun listed(answer: JSONObject?) {
    if (answer == null || answer.has("error")) {
      locked()
      return
    }
    val array = answer.optJSONArray("logins")
    logins = (0 until (array?.length() ?: 0)).mapNotNull { array?.optJSONObject(it) }
    show("")
  }

  /**
   * The app is closed or locked: offer to unlock it, then come back here
   * and carry on by ourselves.
   */
  private fun locked() {
    status.text = getString(if (unlock.waiting) R.string.autofill_waiting else R.string.autofill_locked)
    status.visibility = View.VISIBLE
    list.removeAllViews()
    list.addView(
      Button(this).apply {
        text = getString(R.string.autofill_open)
        isAllCaps = false
        setTextColor(Color.BLACK)
        background = rounded(ACCENT)
        setOnClickListener { unlock.unlock() }
      },
      LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52)),
    )
  }

  private fun show(query: String) {
    val q = query.trim().lowercase()
    val shown = logins.filter {
      q.isEmpty() || it.optString("title").lowercase().contains(q) ||
        it.optString("username").lowercase().contains(q)
    }
    list.removeAllViews()
    status.text = when {
      logins.isEmpty() && form.page != null ->
        getString(R.string.autofill_none_for_site, form.page!!.substringAfter("://"))
      logins.isEmpty() -> getString(R.string.autofill_none)
      shown.isEmpty() -> getString(R.string.autofill_no_results)
      else -> ""
    }
    status.visibility = if (status.text.isEmpty()) View.GONE else View.VISIBLE
    for (login in shown) list.addView(row(login))
  }

  private fun row(login: JSONObject): View {
    val title = login.optString("title")
    val sub = listOf(login.optString("username"), login.optString("vault_name"))
      .filter { it.isNotEmpty() }
      .joinToString(" · ")
    return LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(14), dp(12), dp(14), dp(12))
      background = rounded(PANEL)
      isClickable = true
      isFocusable = true
      layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        bottomMargin = dp(8)
      }
      addView(text(16f, TEXT, title).apply { maxLines = 1; ellipsize = TextUtils.TruncateAt.END })
      if (sub.isNotEmpty()) {
        addView(text(13f, SOFT, sub).apply { maxLines = 1; ellipsize = TextUtils.TruncateAt.END })
      }
      setOnClickListener { fill(login) }
    }
  }

  /** Gets the picked login's username and password and hands them back. */
  private fun fill(login: JSONObject) {
    if (busy) return
    if (!AutofillBroker.connected()) {
      locked()
      return
    }
    busy = true
    val question = JSONObject()
      .put("kind", "fill")
      .put("vault", login.optString("vault"))
      .put("item", login.optString("item"))
      .put("page", form.page ?: JSONObject.NULL)
    worker.execute {
      val answer = AutofillBroker.ask(question, TIMEOUT_MS)
      main.post {
        busy = false
        if (isFinishing) return@post
        when {
          answer == null || answer.optString("error") == "locked" -> locked()
          answer.has("error") -> {
            // Gone, or not for this site: let the person choose instead.
            direct = null
            load()
          }
          else -> finishWith(login.optString("title"), answer.optString("username"), answer.optString("password"))
        }
      }
    }
  }

  private fun finishWith(title: String, username: String, password: String) {
    val label = RemoteViews(packageName, android.R.layout.simple_list_item_1)
    label.setTextViewText(android.R.id.text1, title)
    @Suppress("DEPRECATION")
    val dataset = Dataset.Builder(label)
    var any = false
    form.username?.let {
      if (username.isNotEmpty()) {
        @Suppress("DEPRECATION")
        dataset.setValue(it, AutofillValue.forText(username))
        any = true
      }
    }
    form.password?.let {
      if (password.isNotEmpty()) {
        @Suppress("DEPRECATION")
        dataset.setValue(it, AutofillValue.forText(password))
        any = true
      }
    }
    if (!any) {
      status.text = getString(R.string.autofill_nothing)
      status.visibility = View.VISIBLE
      return
    }
    setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()))
    finish()
  }

  companion object {
    /** The login to fill straight away, when it was tapped under the field. */
    const val EXTRA_VAULT = "io.github.ktnreddy.blackboxus.autofill.VAULT"
    const val EXTRA_ITEM = "io.github.ktnreddy.blackboxus.autofill.ITEM"

    /** How long to wait for the app before saying it's closed. */
    const val TIMEOUT_MS = 4000L
    val PANEL = Color.rgb(24, 24, 27)
    val TEXT = Color.rgb(244, 244, 245)
    val SOFT = Color.rgb(161, 161, 170)
    val MUTED = Color.rgb(113, 113, 122)
    val ACCENT = Color.rgb(255, 106, 26)
    val WARN = Color.rgb(253, 186, 116)
    val WARN_BG = Color.argb(36, 255, 106, 26)
  }
}
