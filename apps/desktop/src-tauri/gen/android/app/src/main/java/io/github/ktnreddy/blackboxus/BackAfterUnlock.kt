package io.github.ktnreddy.blackboxus

import android.app.Activity
import android.app.ActivityManager
import android.content.Intent
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.concurrent.ExecutorService

/**
 * Sends the person to unlock BlackBoxus from an autofill screen, and
 * brings that screen back on its own once they have, so they don't have
 * to find their way back or tap the field again.
 *
 * While waiting it asks the app every second whether it's unlocked (an
 * in-process question, see [AutofillBroker]), for up to five minutes.
 */
class BackAfterUnlock(
  private val activity: Activity,
  private val worker: ExecutorService,
  private val onUnlocked: () -> Unit,
) {
  private val main = Handler(Looper.getMainLooper())
  private var waitingSince = 0L

  val waiting: Boolean get() = waitingSince != 0L

  /** Opens the app to unlock, and starts waiting. */
  fun unlock() {
    waitingSince = System.currentTimeMillis()
    activity.startActivity(
      Intent(activity, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
    )
    main.postDelayed(::check, INTERVAL_MS)
  }

  /** Checks now, as when the person comes back by themselves. */
  fun checkNow() {
    if (waiting) check()
  }

  fun stop() {
    waitingSince = 0L
    main.removeCallbacksAndMessages(null)
  }

  private fun check() {
    if (!waiting || activity.isFinishing) return
    if (System.currentTimeMillis() - waitingSince > GIVE_UP_MS) {
      stop()
      return
    }
    worker.execute {
      val unlocked = AutofillBroker.connected() &&
        AutofillBroker.ask(JSONObject().put("kind", "status"), ASK_MS)?.optBoolean("unlocked") == true
      main.post {
        if (!waiting || activity.isFinishing) return@post
        if (unlocked) {
          stop()
          bringBack()
          onUnlocked()
        } else {
          main.postDelayed(::check, INTERVAL_MS)
        }
      }
    }
  }

  /** Moves this screen's task back in front of the app. */
  private fun bringBack() {
    val manager = activity.getSystemService(ActivityManager::class.java) ?: return
    manager.appTasks.firstOrNull { task ->
      try {
        task.taskInfo?.taskId == activity.taskId
      } catch (e: IllegalArgumentException) {
        false
      }
    }?.moveToFront()
  }

  private companion object {
    const val INTERVAL_MS = 1000L
    const val ASK_MS = 800L
    const val GIVE_UP_MS = 5 * 60 * 1000L
  }
}
