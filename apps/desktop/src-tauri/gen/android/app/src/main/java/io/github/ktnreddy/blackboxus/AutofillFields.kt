package io.github.ktnreddy.blackboxus

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** The fields of a sign-in form, and who is showing it. */
class SignInForm(
  /** The app showing the form. */
  val packageName: String,
  val username: AutofillId?,
  val password: AutofillId?,
  /**
   * The page being filled (`https://example.com`), only when a browser we
   * know says so. Any app can claim a web domain for its own fields, so
   * other apps get no automatic matching.
   */
  val page: String?,
) {
  val ids: List<AutofillId> get() = listOfNotNull(username, password)
}

/** Finds the username and password fields in what another app shows. */
object AutofillFields {
  private enum class Kind { USERNAME, PASSWORD, OTHER, NONE }

  /**
   * Browsers whose web domains are trusted. A browser that leaves out the
   * scheme is treated as `http`, so logins saved for `https` are not
   * offered there.
   */
  private val BROWSERS = setOf(
    "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary",
    "org.chromium.chrome", "org.mozilla.firefox", "org.mozilla.firefox_beta",
    "org.mozilla.fenix", "org.mozilla.focus", "org.mozilla.klar",
    "com.brave.browser", "com.brave.browser_beta", "com.brave.browser_nightly",
    "com.microsoft.emmx", "com.microsoft.emmx.beta", "com.vivaldi.browser",
    "com.opera.browser", "com.opera.browser.beta", "com.opera.gx",
    "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta",
    "com.duckduckgo.mobile.android", "com.kiwibrowser.browser", "com.ecosia.android",
    "org.torproject.torbrowser", "app.vanadium.browser", "com.google.android.apps.chrome",
    "us.spotco.fennec_dos", "org.ironfoxoss.ironfox", "io.github.forkmaintainers.iceraven",
  )

  fun find(structure: AssistStructure): SignInForm {
    val packageName = structure.activityComponent.packageName
    var username: AutofillId? = null
    var password: AutofillId? = null
    var lastText: AutofillId? = null
    var domain: String? = null
    var scheme: String? = null

    fun visit(node: AssistStructure.ViewNode) {
      if (domain == null && !node.webDomain.isNullOrEmpty()) {
        domain = node.webDomain
        scheme = node.webScheme
      }
      val id = node.autofillId
      if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT &&
        node.visibility == View.VISIBLE && node.isEnabled
      ) {
        when (kindOf(node)) {
          Kind.PASSWORD -> if (password == null) {
            password = id
            // A form with no marked username: the text field just before
            // the password usually is one.
            if (username == null) username = lastText
          }
          Kind.USERNAME -> if (username == null && password == null) username = id
          Kind.OTHER -> if (password == null) lastText = id
          Kind.NONE -> {}
        }
      }
      for (i in 0 until node.childCount) visit(node.getChildAt(i))
    }
    for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode)

    val trusted = packageName in BROWSERS
    val host = domain?.trim()?.lowercase()
    val page = if (trusted && !host.isNullOrEmpty()) {
      val s = if (scheme.equals("https", ignoreCase = true)) "https" else "http"
      "$s://$host"
    } else {
      null
    }
    return SignInForm(packageName, username, password, page)
  }

  /** The text typed into the field [id], if it is in [structure]. */
  fun textOf(structure: AssistStructure, id: AutofillId): String? {
    fun visit(node: AssistStructure.ViewNode): String? {
      if (node.autofillId == id) {
        val value = node.autofillValue
        if (value != null && value.isText) return value.textValue.toString()
      }
      for (i in 0 until node.childCount) visit(node.getChildAt(i))?.let { return it }
      return null
    }
    for (i in 0 until structure.windowNodeCount) {
      visit(structure.getWindowNodeAt(i).rootViewNode)?.let { return it }
    }
    return null
  }

  private fun kindOf(node: AssistStructure.ViewNode): Kind {
    val hints = node.autofillHints?.map { it.lowercase() }.orEmpty()
    if (hints.any { "password" in it }) return Kind.PASSWORD
    if (hints.any { "username" in it || "email" in it }) return Kind.USERNAME

    val html = node.htmlInfo
    if (html != null && html.tag.equals("input", ignoreCase = true)) {
      val attrs = html.attributes.orEmpty().associate { (it.first ?: "").lowercase() to (it.second ?: "").lowercase() }
      val type = attrs["type"] ?: "text"
      val auto = attrs["autocomplete"].orEmpty()
      if (type == "password" || "password" in auto) return Kind.PASSWORD
      if (type !in setOf("text", "email", "tel", "")) return Kind.NONE
      if (type == "email" || "username" in auto || "email" in auto) return Kind.USERNAME
      val named = (attrs["name"].orEmpty() + " " + attrs["id"].orEmpty())
      if (listOf("user", "email", "login", "account").any { it in named }) return Kind.USERNAME
      return Kind.OTHER
    }

    val input = node.inputType
    val cls = input and InputType.TYPE_MASK_CLASS
    val variation = input and InputType.TYPE_MASK_VARIATION
    if (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(
        InputType.TYPE_TEXT_VARIATION_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
      )
    ) {
      return Kind.PASSWORD
    }
    if (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD) {
      return Kind.PASSWORD
    }
    if (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(
        InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
        InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS,
      )
    ) {
      return Kind.USERNAME
    }
    val words = listOfNotNull(node.idEntry, node.hint?.toString()).joinToString(" ").lowercase()
    if ("password" in words || "passwd" in words) return Kind.PASSWORD
    if (listOf("user", "email", "login").any { it in words }) return Kind.USERNAME
    return if (cls == InputType.TYPE_CLASS_TEXT || input == 0) Kind.OTHER else Kind.NONE
  }
}
