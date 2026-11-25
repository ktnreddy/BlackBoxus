package io.github.ktnreddy.blackboxus

/**
 * A login typed into another app, between Android's "Save?" prompt and
 * [AutofillSaveActivity]. Kept only in memory, for a few minutes, and
 * cleared once saved or dismissed. Nothing about it is written to disk
 * outside the encrypted vaults.
 */
class PendingSave(
  val title: String,
  val username: String,
  val password: CharArray,
  /** `https://example.com` in a browser we trust, else null. */
  val page: String?,
  val packageName: String,
  val createdAt: Long = System.currentTimeMillis(),
) {
  val expired: Boolean get() = System.currentTimeMillis() - createdAt > LIFETIME_MS

  /** Overwrites the password. */
  fun wipe() = password.fill('\u0000')

  companion object {
    private const val LIFETIME_MS = 5 * 60 * 1000L
    private val lock = Any()
    private var current: PendingSave? = null

    /** Replaces any earlier pending save. */
    fun put(save: PendingSave) = synchronized(lock) {
      current?.wipe()
      current = save
    }

    /** The pending save, if there is one and it hasn't expired. */
    fun get(): PendingSave? = synchronized(lock) {
      val save = current
      if (save != null && save.expired) {
        save.wipe()
        current = null
      }
      current
    }

    fun clear() = synchronized(lock) {
      current?.wipe()
      current = null
    }
  }
}
