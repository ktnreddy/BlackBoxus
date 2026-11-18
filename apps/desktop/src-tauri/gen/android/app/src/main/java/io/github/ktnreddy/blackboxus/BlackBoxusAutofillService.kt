package io.github.ktnreddy.blackboxus

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
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

  override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
    val structure = request.fillContexts.lastOrNull()?.structure
    if (structure == null || structure.activityComponent.packageName == packageName) {
      callback.onSuccess(null)
      return
    }
    val form = AutofillFields.find(structure)
    if (form.ids.isEmpty()) {
      callback.onSuccess(null)
      return
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
    val offer = RemoteViews(packageName, android.R.layout.simple_list_item_1)
    offer.setTextViewText(android.R.id.text1, getString(R.string.autofill_offer))
    @Suppress("DEPRECATION")
    val response = FillResponse.Builder()
      .setAuthentication(form.ids.toTypedArray(), sender, offer)
      .build()
    callback.onSuccess(response)
  }

  /** Saving from other apps isn't offered; logins are added in the app. */
  override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
    callback.onSuccess()
  }
}
