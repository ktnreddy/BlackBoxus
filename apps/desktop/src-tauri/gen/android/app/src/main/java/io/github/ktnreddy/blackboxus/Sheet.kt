package io.github.ktnreddy.blackboxus

import android.app.Activity
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ScrollView

/**
 * Shows an autofill screen as a sheet rising from the bottom over the app
 * being filled, like Android's own password manager, rather than as a
 * full screen of its own. Tapping above the sheet closes it.
 */
object Sheet {
  private val BG = Color.rgb(18, 18, 20)
  private val HANDLE = Color.rgb(63, 63, 70)

  private fun dp(activity: Activity, value: Int): Int =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), activity.resources.displayMetrics).toInt()

  /** Sets the window up as a sheet: full width, at the bottom, dimming the app behind. */
  fun show(activity: Activity) {
    val window = activity.window
    window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
    window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    window.setGravity(Gravity.BOTTOM)
    window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
    window.setDimAmount(0.55f)
    @Suppress("DEPRECATION")
    window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    activity.setFinishOnTouchOutside(true)
  }

  /** The small bar at the top of the sheet. */
  fun handle(activity: Activity): View = View(activity).apply {
    background = GradientDrawable().apply {
      setColor(HANDLE)
      cornerRadius = dp(activity, 2).toFloat()
    }
  }

  /**
   * [content] on the sheet's rounded panel, scrolling when it's taller
   * than three quarters of the screen.
   */
  fun wrap(activity: Activity, content: View): View {
    val maxHeight = (activity.resources.displayMetrics.heightPixels * 0.75f).toInt()
    val scroll = object : ScrollView(activity) {
      override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(maxHeight, View.MeasureSpec.AT_MOST))
      }
    }
    scroll.isFillViewport = true
    scroll.addView(content)
    return FrameLayout(activity).apply {
      background = GradientDrawable().apply {
        setColor(BG)
        val r = dp(activity, 24).toFloat()
        cornerRadii = floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f)
      }
      // Clear of the navigation bar on phones drawn edge to edge.
      setOnApplyWindowInsetsListener { view, insets ->
        @Suppress("DEPRECATION")
        view.setPadding(0, 0, 0, insets.systemWindowInsetBottom)
        insets
      }
      addView(scroll, FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }
  }
}
