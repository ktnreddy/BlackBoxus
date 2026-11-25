package io.github.ktnreddy.blackboxus

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.Presentations
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import androidx.autofill.inline.v1.InlineSuggestionUi
import java.util.concurrent.atomic.AtomicInteger

/**
 * Offers "Fill with BlackBoxus" on sign-in forms in other apps.
 *
 * Nothing from the vaults is in the offer: choosing it opens
 * [AutofillPickerActivity], where the person picks a login, and only that
 * login's username and password go back to Android.
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
   * "Fill with BlackBoxus" for the keyboard's suggestion strip, when the
   * keyboard asks for one (Android 11+); null means the dropdown is used.
   */
  private fun inlineOffer(request: FillRequest): InlinePresentation? {
    if (Build.VERSION.SDK_INT < 30) return null
    val spec = request.inlineSuggestionsRequest?.inlinePresentationSpecs?.firstOrNull() ?: return null
    // Long-pressing the suggestion opens the app, as Android requires.
    val attribution = PendingIntent.getActivity(
      this,
      0,
      Intent(this, MainActivity::class.java),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
    val content = InlineSuggestionUi.newContentBuilder(attribution)
      .setTitle(getString(R.string.autofill_offer))
      .setStartIcon(Icon.createWithResource(this, R.mipmap.ic_launcher))
      .build()
    return InlinePresentation(content.slice, spec, false)
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
    val intent = Intent(this, AutofillPickerActivity::class.java)
    // Mutable so Android can add the form's structure; the intent names our
    // own activity, so nothing else can receive it.
    val sender = PendingIntent.getActivity(
      this,
      requests.incrementAndGet(),
      intent,
      PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
    ).intentSender
    val shown = RemoteViews(packageName, android.R.layout.simple_list_item_1)
    shown.setTextViewText(android.R.id.text1, getString(R.string.autofill_offer))
    AutofillLog.request(this, app, "offered", form.username != null, form.password != null)
    val ids = form.ids.toTypedArray()
    val inline = inlineOffer(request)
    val response = FillResponse.Builder()
    when {
      inline != null && Build.VERSION.SDK_INT >= 33 ->
        response.setAuthentication(
          ids,
          sender,
          Presentations.Builder().setMenuPresentation(shown).setInlinePresentation(inline).build(),
        )
      inline != null && Build.VERSION.SDK_INT >= 30 ->
        @Suppress("DEPRECATION")
        response.setAuthentication(ids, sender, shown, inline)
      else ->
        @Suppress("DEPRECATION")
        response.setAuthentication(ids, sender, shown)
    }
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
