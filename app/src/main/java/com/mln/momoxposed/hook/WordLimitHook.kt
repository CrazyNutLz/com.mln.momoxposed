package com.mln.momoxposed.hook

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * 单词上限 hook
 *
 * 纯 Java 反射方案：不再依赖 DexKit，由 MomoHookEntry 统一 hook 所有无参 int 方法后，
 * 在运行时通过返回值范围（600~20000）锁定目标方法，然后强制返回 99666。
 */
class WordLimitHook {

    companion object {
        private const val REPLACEMENT_VALUE = 99666
        private const val MIN_LIMIT = 600
        private const val MAX_LIMIT = 20000
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
        // 通过返回值范围确认目标：单词上限通常在 600~20000 之间
        if (result in (MIN_LIMIT + 1) until MAX_LIMIT) {
            this.className = declaringClassName
            this.methodName = methodName
            XposedBridge.log("MomoXposed: 锁定单词上限 $className.$methodName = $result")
            Handler(Looper.getMainLooper()).post {
                Toast.makeText(context, "已找到单词数量: $className.$methodName", Toast.LENGTH_SHORT).show()
            }
            onFound()
        }
    }

    /** 应用 hook：将单词上限强制替换为 REPLACEMENT_VALUE */
    fun apply(classLoader: ClassLoader) {
        if (!isFound) return
        try {
            val cls = XposedHelpers.findClass(className, classLoader)
            XposedHelpers.findAndHookMethod(cls, methodName, object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    param.result = REPLACEMENT_VALUE
                }
            })
            XposedBridge.log("MomoXposed: 单词上限 hook 已生效 -> $className.$methodName")
        } catch (_: Throwable) { }
    }
}
