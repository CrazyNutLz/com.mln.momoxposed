package com.mln.momoxposed

import android.app.Application
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import com.mln.momoxposed.hook.SecurityBypassHook
import com.mln.momoxposed.hook.UserLevelHook
import com.mln.momoxposed.hook.WordLimitHook
import com.mln.momoxposed.util.HookCache
import com.mln.momoxposed.util.HookData
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

/**
 * Xposed 模块入口类
 *
 * 加固壳环境下 DexKit 无法解析内存中的真实 DEX（壳抹除了 Magic Header 或破坏了连续内存结构），
 * 因此采用纯 Java 反射方案：通过 DexFile.entries() 枚举所有类，结合 loadClass + 包名过滤
 * 发现目标类，再扫描并 hook 无参 int 方法，运行时通过返回值范围锁定目标。
 */
class MomoHookEntry : IXposedHookLoadPackage {

    companion object {
        private const val TARGET_PACKAGE = "com.maimemo.android.momo"
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PACKAGE) return

        // hook Application.attach — 壳完成 attachBaseContext 后触发
        XposedHelpers.findAndHookMethod(
            Application::class.java, "attach", Context::class.java,
            object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    val context = param.args[0] as Context
                    val classLoader = context.classLoader ?: return
                    doHook(context, classLoader)
                }
            }
        )

        // 兜底：onCreate 时壳已完全就绪
//        XposedHelpers.findAndHookMethod(
//            Application::class.java, "onCreate",
//            object : XC_MethodHook() {
//                override fun beforeHookedMethod(param: MethodHookParam) {
//                    val app = param.thisObject as Application
//                    val classLoader = app.classLoader ?: return
//                    doHook(app.applicationContext, classLoader)
//                }
//            }
//        )
    }

    private fun doHook(context: Context, classLoader: ClassLoader) {
        // 绕过 App 的 hook 检测，必须在其他 hook 之前执行
//        SecurityBypassHook().apply(classLoader)

        val versionCode = context.packageManager
            .getPackageInfo(context.packageName, 0).versionCode

        val cached = HookCache.load(context, versionCode)
        if (cached != null) {
            applyHooks(cached, classLoader)
        } else {
            discoverAndHook(classLoader, context, versionCode)
        }
    }

    /** 从缓存数据直接应用 hook */
    private fun applyHooks(data: HookData, classLoader: ClassLoader) {
        UserLevelHook().apply {
            className = data.userLevelClass
            methodName = data.userLevelMethod
            apply(classLoader)
        }
        WordLimitHook().apply {
            className = data.wordLimitClass
            methodName = data.wordLimitMethod
            apply(classLoader)
        }
    }

    /**
     * 使用纯 Java 反射扫描目标应用，发现方法后自动缓存
     *
     * 流程：
     * 1. 通过 DexFile.entries() 枚举 ClassLoader 中的所有类名
     * 2. 按各 Hook 的目标类前缀精确过滤，减少候选范围
     * 3. 对目标类扫描无参且返回 int 的方法并 hook
     * 4. 运行时通过返回值范围锁定目标
     */
    private fun discoverAndHook(classLoader: ClassLoader, context: Context, versionCode: Int) {
        Handler(Looper.getMainLooper()).post {
            Toast.makeText(context, "正在寻找 hook 函数...", Toast.LENGTH_SHORT).show()
        }

        val wordLimitHook = WordLimitHook()
        val userLevelHook = UserLevelHook()

        val startTime = System.currentTimeMillis()

        // 从 DexFile 中枚举所有类名
        val allClassNames = enumerateClassNames(classLoader)
        XposedBridge.log("MomoXposed: 枚举到 ${allClassNames.size} 个类名")

        // 按各 Hook 的目标类前缀过滤
        // WordLimitHook 目标: com.maimemo.android.momo.User.Z()
        val wordLimitClasses = filterClasses(classLoader, allClassNames, "com.maimemo.android.momo.User")
        // UserLevelHook 目标: com.maimemo.android.momo.user.level.k.m()
        val userLevelClasses = filterClasses(classLoader, allClassNames, "com.maimemo.android.momo.user.level")

        XposedBridge.log("MomoXposed: 单词上限候选类 ${wordLimitClasses.size} 个, 用户等级候选类 ${userLevelClasses.size} 个")

        // 分别 hook 两个目标前缀下的无参 int 方法
        var hookedCount = 0
        hookedCount += hookIntMethods(userLevelClasses, classLoader, wordLimitHook, userLevelHook, context, versionCode)
        hookedCount += hookIntMethods(wordLimitClasses, classLoader, wordLimitHook, userLevelHook, context, versionCode)

        val elapsed = System.currentTimeMillis() - startTime
        XposedBridge.log("MomoXposed: 反射扫描完成，hook 了 $hookedCount 个候选方法，耗时 ${elapsed}ms")
    }

    /** 判断类名是否为指定前缀下的直接类（排除内部类，即名称中含 `$` 的类） */
    private fun isDirectClass(className: String, prefix: String): Boolean {
        if (!className.startsWith(prefix)) return false
        val suffix = className.substring(prefix.length)
        return '$' !in suffix
    }

    /**
     * 按类名前缀过滤：先尝试从类名直接匹配，未命中则加载全部类检查实际类名（穿透壳混淆）
     */
    private fun filterClasses(
        classLoader: ClassLoader,
        allClassNames: List<String>,
        prefix: String
    ): List<Class<*>> {
        // 第一轮：类名前缀直接匹配
        val directMatches = allClassNames
            .filter { isDirectClass(it, prefix) }
            .mapNotNull { name ->
                try { classLoader.loadClass(name) } catch (_: ClassNotFoundException) { null }
            }
        if (directMatches.isNotEmpty()) return directMatches

        // 兜底：壳混淆了类名，加载全部类检查实际类名
        XposedBridge.log("MomoXposed: 前缀 '$prefix' 未直接命中，加载全部类过滤...")
        return allClassNames.mapNotNull { name ->
            try {
                val cls = classLoader.loadClass(name)
                if (isDirectClass(cls.name, prefix)) cls else null
            } catch (_: ClassNotFoundException) { null }
        }
    }

    /**
     * 对给定类列表中的无参 int 方法进行 hook，运行时由各 Hook 判断返回值范围
     */
    private fun hookIntMethods(
        classes: List<Class<*>>,
        classLoader: ClassLoader,
        wordLimitHook: WordLimitHook,
        userLevelHook: UserLevelHook,
        context: Context,
        versionCode: Int
    ): Int {
        var count = 0
        for (cls in classes) {
            val methods = cls.declaredMethods.filter {
                it.parameterTypes.isEmpty() && it.returnType == Int::class.javaPrimitiveType
            }
            for (method in methods) {
                try {
                    XposedBridge.hookAllMethods(cls, method.name, object : XC_MethodHook() {
                        override fun afterHookedMethod(param: MethodHookParam) {
                            val result = param.result as? Int ?: return
                            userLevelHook.onMethodResult(cls.name, method.name, result, context) {
                                tryPersist(wordLimitHook, userLevelHook, context, versionCode)
                            }
                            wordLimitHook.onMethodResult(cls.name, method.name, result, context) {
                                tryPersist(wordLimitHook, userLevelHook, context, versionCode)
                            }
                        }
                    })
                    count++
                } catch (_: Throwable) { }
            }
        }
        return count
    }

    /**
     * 从 ClassLoader 的 DexFile 中枚举所有类名
     * 加固壳环境下，DexFile.entries() 返回的是壳解密后的真实类名
     */
    private fun enumerateClassNames(classLoader: ClassLoader): List<String> {
        val result = mutableListOf<String>()
        try {
            val pathListField = Class.forName("dalvik.system.BaseDexClassLoader")
                .getDeclaredField("pathList")
            pathListField.isAccessible = true
            val dexPathList = pathListField.get(classLoader)

            val dexElementsField = dexPathList.javaClass.getDeclaredField("dexElements")
            dexElementsField.isAccessible = true
            val dexElements = dexElementsField.get(dexPathList) as Array<*>

            for (element in dexElements) {
                if (element == null) continue
                val dexFileField = element.javaClass.getDeclaredField("dexFile")
                dexFileField.isAccessible = true
                val dexFile = dexFileField.get(element) as? dalvik.system.DexFile ?: continue

                val entries = dexFile.entries()
                while (entries.hasMoreElements()) {
                    result.add(entries.nextElement())
                }
            }
        } catch (e: Exception) {
            XposedBridge.log("MomoXposed: 枚举类名失败: ${e.message}")
        }
        return result
    }

    /** 单词上限是必要条件，找到后才持久化（用户等级可为空） */
    private fun tryPersist(
        wordLimitHook: WordLimitHook,
        userLevelHook: UserLevelHook,
        context: Context,
        versionCode: Int
    ) {
        if (!wordLimitHook.isFound) return
        HookCache.save(
            context,
            HookData(
                wordLimitClass = wordLimitHook.className,
                wordLimitMethod = wordLimitHook.methodName,
                userLevelClass = userLevelHook.className,
                userLevelMethod = userLevelHook.methodName
            ),
            versionCode
        )
    }
}
