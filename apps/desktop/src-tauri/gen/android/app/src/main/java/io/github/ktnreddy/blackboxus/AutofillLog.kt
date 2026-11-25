package io.github.ktnreddy.blackboxus

import android.content.Context
import org.json.JSONObject

/**
 * What happened the last time Android asked BlackBoxus about a form, so
 * Settings can say why "Fill with BlackBoxus" did or didn't appear.
 *
 * Only the asking app's package name, the time and the outcome are kept,
 * on this phone, and never anything typed into the form. The file is
 * excluded from backups like everything else the app stores.
 */
object AutofillLog {
  private const val FILE = "autofill_last"

  /** Android connected to the service: it is chosen and running. */
  fun connected(context: Context) {
    prefs(context).edit().putLong("connected_at", System.currentTimeMillis()).apply()
  }

  /**
   * One request: [app] asked, [outcome] is `offered`, `no_fields`,
   * `own_app`, `no_form` or `error`.
   */
  fun request(context: Context, app: String?, outcome: String, username: Boolean, password: Boolean) {
    prefs(context).edit()
      .putLong("at", System.currentTimeMillis())
      .putString("app", app.orEmpty())
      .putString("outcome", outcome)
      .putBoolean("username", username)
      .putBoolean("password", password)
      .apply()
  }

  /** The last request and connection, as shown in Settings. */
  fun last(context: Context): JSONObject {
    val p = prefs(context)
    return JSONObject().apply {
      put("connected_at", p.getLong("connected_at", 0))
      put("at", p.getLong("at", 0))
      put("app", p.getString("app", ""))
      put("outcome", p.getString("outcome", ""))
      put("username", p.getBoolean("username", false))
      put("password", p.getBoolean("password", false))
    }
  }

  private fun prefs(context: Context) = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
}
