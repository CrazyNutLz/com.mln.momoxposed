package com.mln.momoxposed.hook

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * 用户等级 hook
 *
 * 纯 Java 反射方案：由 MomoHookEntry 统一 hook 所有无参 int 方法后，
 * 在运行时通过返回值范围（1~20）锁定目标方法，然后强制返回 21（最高等级）。
 */
class UserLevelHook {

    companion object {
        private const val REPLACEMENT_LEVEL = 21
        private const val MIN_LEVEL = 1
        private const val MAX_LEVEL = 21
    }

    var className: String = ""
    var methodName: String = ""
    val isFound: Boolean get() = className.isNotEmpty() && methodName.isNotEmpty()

    /**
     * 由 MomoHookEntry 在每个候选方法的 afterHookedMethod 中回调。
     * 通过返回值范围判断是否为目标方法，锁定后替换返回值。
     */
    fun onMethodResult(
        declaringClassName: String,
        methodName: String,
        result: Int,
        context: Context,
        onFound: () -> Unit
    ) {
        if (isFound) return
        // 通过返回值范围确认目标：用户等级通常在 1~20 之间
        if (result in MIN_LEVEL until MAX_LEVEL) {
            this.className = declaringClassName
            this.methodName = methodName
            XposedBridge.log("MomoXposed: 锁定用户等级 $className.$methodName = $result")
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(context, "已找到用户等级: $className.$methodName", Toast.LENGTH_SHORT).show()
            }
            onFound()
        }
    }

    /** 应用 hook：将用户等级强制替换为 REPLACEMENT_LEVEL */
    fun apply(classLoader: ClassLoader) {
        if (!isFound) return
        try {
            val cls = XposedHelpers.findClass(className, classLoader)
            XposedHelpers.findAndHookMethod(cls, methodName, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    param.result = REPLACEMENT_LEVEL
                }
            })
            XposedBridge.log("MomoXposed: 用户等级 hook 已生效 -> $className.$methodName")
        } catch (_: Throwable) { }
    }
}
