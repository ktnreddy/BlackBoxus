package io.github.ktnreddy.blackboxus

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class AutofillAnswerArgs {
  var id: Long = 0
  var body: String = ""
}

/**
 * The Rust side's end of [AutofillBroker]. Only Rust calls these commands:
 * the window has no permission for them.
 */
@TauriPlugin
class AutofillPlugin(private val activity: Activity) : Plugin(activity) {
  /** Whether BlackBoxus is the phone's autofill service. */
  @Command
  fun status(invoke: Invoke) {
    val manager = activity.getSystemService(AutofillManager::class.java)
    val enabled = manager != null && manager.isAutofillSupported && manager.hasEnabledAutofillServices()
    invoke.resolve(JSObject().apply { put("enabled", enabled) })
  }

  /** Opens the phone's setting for choosing the autofill service. */
  @Command
  fun openSettings(invoke: Invoke) {
    val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
      .setData(Uri.parse("package:" + activity.packageName))
    try {
      activity.startActivity(intent)
    } catch (e: ActivityNotFoundException) {
      activity.startActivity(Intent(Settings.ACTION_SETTINGS))
    }
    invoke.resolve()
  }

  /** Resolves with the next question once the picker asks one. */
  @Command
  fun next(invoke: Invoke) {
    AutofillBroker.waitForQuestion { question -> invoke.resolve(JSObject(question.toString())) }
  }

  /** Passes Rust's answer back to the picker. */
  @Command
  fun answer(invoke: Invoke) {
    val args = invoke.parseArgs(AutofillAnswerArgs::class.java)
    AutofillBroker.answer(args.id, args.body)
    invoke.resolve()
  }
}
