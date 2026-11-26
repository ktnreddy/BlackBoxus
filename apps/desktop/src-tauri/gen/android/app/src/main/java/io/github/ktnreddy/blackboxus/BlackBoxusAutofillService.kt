package io.github.ktnreddy.blackboxus

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import androidx.autofill.inline.v1.InlineSuggestionUi
import java.util.concurrent.atomic.AtomicInteger

/**
 * Offers logins on sign-in forms in other apps, the way Android's own
 * password manager does: in a browser, the logins saved for the site are
 * listed under the field (title and username only) and fill in one tap;
 * "Fill with BlackBoxus" opens [AutofillPickerActivity] to choose another,
 * or to unlock first. A password only leaves the vaults once tapped.
 */
class BlackBoxusAutofillService : AutofillService() {
  private val requests = AtomicInteger()

  override fun onConnected() {
    super.onConnected()
    AutofillLog.connected(this)
  }

  override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
    val structure = request.fillContexts.lastOrNull()?.structure
    val app = structure?.activityComponent?.packageName
    // Whatever goes wrong below, Android gets an answer: a request left
    // unanswered blocks autofill in that app until it times out.
    val response = try {
      offer(request, structure, app)
    } catch (e: RuntimeException) {
      AutofillLog.request(this, app, "error", false, false)
      null
    }
    callback.onSuccess(response)
  }

  /**
   * A suggestion for the keyboard's suggestion strip, when the keyboard
   * asks for them (Android 11+); null means only the dropdown is used.
   * [index] picks the keyboard's size for the nth suggestion.
   */
  private fun inline(request: FillRequest, index: Int, title: String, subtitle: String?): InlinePresentation? {
    if (Build.VERSION.SDK_INT < 30) return null
    val specs = request.inlineSuggestionsRequest?.inlinePresentationSpecs ?: return null
    if (specs.isEmpty() || index >= request.inlineSuggestionsRequest!!.maxSuggestionCount) return null
    val spec = specs[minOf(index, specs.size - 1)]
    // Long-pressing a suggestion opens the app, as Android requires.
    val attribution = PendingIntent.getActivity(
      this,
      0,
      Intent(this, MainActivity::class.java),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    val content = InlineSuggestionUi.newContentBuilder(attribution)
      .setTitle(title)
      .setStartIcon(Icon.createWithResource(this, R.mipmap.ic_launcher))
    if (!subtitle.isNullOrEmpty()) content.setSubtitle(subtitle)
    return InlinePresentation(content.build().slice, spec, false)
  }

  /** One line of the dropdown: a title, and a smaller line under it. */
  private fun menuLine(title: String, subtitle: String?): RemoteViews {
    val line = RemoteViews(packageName, R.layout.autofill_item)
    line.setTextViewText(R.id.autofill_item_title, title)
    if (subtitle.isNullOrEmpty()) {
      line.setViewVisibility(R.id.autofill_item_subtitle, android.view.View.GONE)
    } else {
      line.setTextViewText(R.id.autofill_item_subtitle, subtitle)
    }
    return line
  }

  /**
   * Opens [AutofillPickerActivity]: for one login ([vault] and [item]),
   * which fills it straight away, or with neither, to choose or unlock.
   * Mutable so Android can add the form's structure; the intent names our
   * own activity, so nothing else can receive it.
   */
  private fun picker(vault: String?, item: String?): android.content.IntentSender {
    val intent = Intent(this, AutofillPickerActivity::class.java)
    if (vault != null && item != null) {
      intent.putExtra(AutofillPickerActivity.EXTRA_VAULT, vault).putExtra(AutofillPickerActivity.EXTRA_ITEM, item)
    }
    return PendingIntent.getActivity(
      this,
      requests.incrementAndGet(),
      intent,
      PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
    ).intentSender
  }

  /**
   * One choice in the dropdown and keyboard. Nothing from the vaults is in
   * it but a title and username: the password is only fetched once the
   * person taps it, by [AutofillPickerActivity].
   */
  @Suppress("DEPRECATION")
  private fun choice(
    request: FillRequest,
    ids: List<android.view.autofill.AutofillId>,
    index: Int,
    title: String,
    subtitle: String?,
    sender: android.content.IntentSender,
  ): Dataset {
    val dataset = Dataset.Builder(menuLine(title, subtitle))
    inline(request, index, title, subtitle)?.let { dataset.setInlinePresentation(it) }
    for (id in ids) dataset.setValue(id, null)
    dataset.setAuthentication(sender)
    return dataset.build()
  }

  /**
   * The logins saved for [page], asked of the app while it's open and
   * unlocked; null when it's closed or locked. Only titles and usernames.
   */
  private fun loginsFor(page: String): List<org.json.JSONObject>? {
    if (!AutofillBroker.connected()) return null
    val answer = AutofillBroker.ask(
      org.json.JSONObject().put("kind", "logins").put("page", page),
      QUICK_MS,
    ) ?: return null
    if (answer.has("error")) return null
    val array = answer.optJSONArray("logins") ?: return emptyList()
    return (0 until array.length()).mapNotNull { array.optJSONObject(it) }
  }

  private fun offer(
    request: FillRequest,
    structure: android.app.assist.AssistStructure?,
    app: String?,
  ): FillResponse? {
    if (structure == null) {
      AutofillLog.request(this, app, "no_form", false, false)
      return null
    }
    if (app == packageName) {
      AutofillLog.request(this, app, "own_app", false, false)
      return null
    }
    val form = AutofillFields.find(structure)
    if (form.ids.isEmpty()) {
      AutofillLog.request(this, app, "no_fields", false, false)
      return null
    }
    AutofillLog.request(this, app, "offered", form.username != null, form.password != null)
    val response = FillResponse.Builder()
    // In a browser, the logins saved for the site, ready to fill in one tap.
    val page = form.page
    val logins = page?.let { loginsFor(it) }
    var index = 0
    logins?.take(MAX_SHOWN)?.forEach { login ->
      val username = login.optString("username")
      val title = login.optString("title")
      response.addDataset(
        choice(
          request,
          form.ids,
          index++,
          username.ifEmpty { title },
          if (username.isEmpty()) getString(R.string.autofill_no_username) else title,
          picker(login.optString("vault"), login.optString("item")),
        ),
      )
    }
    // Then: choose another login, or unlock first.
    val unlocked = logins != null || (page == null && AutofillBroker.connected() && unlockedNow())
    response.addDataset(
      choice(
        request,
        form.ids,
        index,
        getString(if (unlocked) R.string.autofill_offer else R.string.autofill_unlock_offer),
        if (logins != null && logins.size > MAX_SHOWN) getString(R.string.autofill_more, logins.size - MAX_SHOWN) else null,
        picker(null, null),
      ),
    )
    // Offer to save what's typed, once the form is sent. Needs a password
    // field; the username is saved too when there is one.
    form.password?.let { password ->
      val types = SaveInfo.SAVE_DATA_TYPE_PASSWORD or
        (if (form.username != null) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
      val save = SaveInfo.Builder(types, arrayOf(password))
      form.username?.let { save.setOptionalIds(arrayOf(it)) }
      response.setSaveInfo(save.build())
    }
    return response.build()
  }

  /** Whether the app is open and unlocked, asked quickly. */
  private fun unlockedNow(): Boolean =
    AutofillBroker.ask(org.json.JSONObject().put("kind", "status"), QUICK_MS)?.optBoolean("unlocked") == true

  private companion object {
    /** Android waits a few seconds for an answer; never use most of it. */
    const val QUICK_MS = 1200L
    /** Logins listed directly under the field, before "Fill with BlackBoxus". */
    const val MAX_SHOWN = 4
  }

  /**
   * The person chose "Save" in Android's prompt. What they typed is kept
   * in memory ([PendingSave]) and [AutofillSaveActivity] asks them to
   * confirm; nothing is saved without that.
   */
  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    try {
      var username = ""
      var password: String? = null
      var page: String? = null
      var app: String? = null
      // A form may span several screens (username first, then password).
      for (context in request.fillContexts) {
        val structure = context.structure
        val form = AutofillFields.find(structure)
        app = form.packageName
        page = form.page ?: page
        form.username?.let { id -> AutofillFields.textOf(structure, id)?.takeIf { it.isNotBlank() }?.let { username = it.trim() } }
        form.password?.let { id -> AutofillFields.textOf(structure, id)?.takeIf { it.isNotEmpty() }?.let { password = it } }
      }
      val typed = password
      if (typed == null || app == null || app == packageName) {
        callback.onSuccess()
        return
      }
      val title = page?.substringAfter("://")?.removePrefix("www.") ?: appLabel(app)
      PendingSave.put(PendingSave(title, username, typed.toCharArray(), page, app))
      val confirm = PendingIntent.getActivity(
        this,
        requests.incrementAndGet(),
        Intent(this, AutofillSaveActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
      ).intentSender
      callback.onSuccess(confirm)
    } catch (e: RuntimeException) {
      callback.onFailure(getString(R.string.save_failed, e.javaClass.simpleName))
    }
  }

  /** The name an app shows on the home screen, or its package name. */
  private fun appLabel(app: String): String = try {
    val info = packageManager.getApplicationInfo(app, 0)
    packageManager.getApplicationLabel(info).toString()
  } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
    app
  }
}
