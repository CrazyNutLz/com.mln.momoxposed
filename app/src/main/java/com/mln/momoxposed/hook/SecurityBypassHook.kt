package com.mln.momoxposed.hook

import dalvik.system.DexFile
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers

/**
 * 绕过 com.maimemo.android.momo.security.a 的 hook 检测
 *
 * 检测逻辑（smali 分析）：
 * 1. ClassLoader.getSystemClassLoader().loadClass("de.robv.android.xposed.XposedBridge")
 *    → 如果能找到该类，判定注入
 * 2. 遍历异常堆栈，检查 className 是否包含 Xposed/Substrate 框架类名
 *    → 匹配到则判定注入
 *
 * 绕过方式：hook security.a.a()，在 beforeHookedMethod 中：
 * - 反射构造内部类 a$d（检测结果容器）
 * - 将 a$d.a 设为 false（表示未检测到注入）
 * - 通过 param.result = a$dInstance 提前返回，跳过整个检测逻辑
 */
class SecurityBypassHook {

    fun apply(classLoader: ClassLoader) {
        try {
            val securityClass = XposedHelpers.findClass(
                "com.maimemo.android.momo.security.a", classLoader
            )
            val resultClass = XposedHelpers.findClass(
                "com.maimemo.android.momo.security.a\$d", classLoader
            )

            XposedHelpers.findAndHookMethod(securityClass, "a",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        try {
                            // 构造 a$d 实例（内部类，构造器需传入外部类实例）
                            val resultObj = resultClass.getConstructor(securityClass)
                                .newInstance(param.thisObject)
                            // 设置 a = false（未检测到注入）
                            XposedHelpers.setBooleanField(resultObj, "a", false)
                            // 提前返回，跳过整个检测方法
                            param.result = resultObj
                        } catch (e: Throwable) {
                            XposedBridge.log("SecurityBypassHook: 绕过失败 - ${e.message}")
                        }
                    }
                }
            )
            XposedBridge.log("SecurityBypassHook: 已 hook security.a.a() 绕过检测")
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: hook security.a.a() 失败 - ${e.message}")
        }

        // hook Settings$Bool.f() — 当 INJECTED 枚举调用时强制返回 false
        // SplashActivity.u3() 会检查 INJECTED.f()，如果为 true 则 finish()
        try {
            val settingsBoolClass = XposedHelpers.findClass(
                "com.maimemo.android.momo.util.Settings\$Bool", classLoader
            )
            val injectedField = settingsBoolClass.getField("INJECTED")
            val injectedValue = injectedField.get(null)

            XposedHelpers.findAndHookMethod(settingsBoolClass, "f",
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (param.thisObject == injectedValue) {
                            XposedBridge.log("SecurityBypassHook: [绕过] INJECTED.f() → false")
                            param.result = false
                        }
                    }
                }
            )
            // 同时阻止 h(true) 将 INJECTED 设为 true
            XposedHelpers.findAndHookMethod(settingsBoolClass, "h",
                Boolean::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        if (param.thisObject == injectedValue) {
                            XposedBridge.log("SecurityBypassHook: [绕过] INJECTED.h(${param.args[0]}) → 阻止写入")
                            param.result = null
                        }
                    }
                }
            )
            XposedBridge.log("SecurityBypassHook: 已 hook Settings\$Bool INJECTED")
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: hook Settings\$Bool 失败 - ${e.message}")
        }

        // 拦截 System.exit()，打印调用栈并阻止杀进程
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", classLoader, "exit",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val stack = Thread.currentThread().stackTrace.joinToString("\n  ") {
                            "${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})"
                        }
                        XposedBridge.log("SecurityBypassHook: [拦截] System.exit(${param.args[0]}) 被调用!\n  $stack")
                        param.result = null
                    }
                }
            )
            XposedBridge.log("SecurityBypassHook: 已 hook System.exit()")
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: hook System.exit() 失败 - ${e.message}")
        }

        // 拦截 Process.killProcess()，打印调用栈并阻止杀进程
        try {
            XposedHelpers.findAndHookMethod("android.os.Process", classLoader, "killProcess",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val stack = Thread.currentThread().stackTrace.joinToString("\n  ") {
                            "${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})"
                        }
                        XposedBridge.log("SecurityBypassHook: [拦截] Process.killProcess(${param.args[0]}) 被调用!\n  $stack")
                        param.result = null
                    }
                }
            )
            XposedBridge.log("SecurityBypassHook: 已 hook Process.killProcess()")
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: hook Process.killProcess() 失败 - ${e.message}")
        }

        // 拦截 Runtime.halt()，直接终止 JVM 且不触发 shutdown hooks
        try {
            XposedHelpers.findAndHookMethod(Runtime::class.java, "halt",
                Int::class.javaPrimitiveType,
                object : XC_MethodHook() {
                    override fun beforeHookedMethod(param: MethodHookParam) {
                        val stack = Thread.currentThread().stackTrace.joinToString("\n  ") {
                            "${it.className}.${it.methodName}(${it.fileName}:${it.lineNumber})"
                        }
                        XposedBridge.log("SecurityBypassHook: [拦截] Runtime.halt(${param.args[0]}) 被调用!\n  $stack")
                        param.result = null
                    }
                }
            )
            XposedBridge.log("SecurityBypassHook: 已 hook Runtime.halt()")
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: hook Runtime.halt() 失败 - ${e.message}")
        }

        // 扫描 security 包下所有类和方法，hook 无参方法以追踪调用
        scanSecurityPackage(classLoader)
    }

    private fun scanSecurityPackage(classLoader: ClassLoader) {
        try {
            // 从 DexFile 枚举类名，过滤 security 包
            val securityClasses = mutableListOf<String>()
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
                val dexFile = dexFileField.get(element) as? DexFile ?: continue
                val entries = dexFile.entries()
                while (entries.hasMoreElements()) {
                    val name = entries.nextElement()
                    if (name.startsWith("com.maimemo.android.momo.security")) {
                        securityClasses.add(name)
                    }
                }
            }

            XposedBridge.log("SecurityBypassHook: [扫描] security 包共 ${securityClasses.size} 个类")

            for (className in securityClasses) {
                try {
                    val cls = classLoader.loadClass(className)
                    val methods = cls.declaredMethods
                    val simpleName = cls.name
                    XposedBridge.log("SecurityBypassHook: [扫描] $simpleName (${methods.size} 个方法)")

                    for (method in methods) {
                        val params = method.parameterTypes.joinToString(", ") { it.simpleName }
                        val sig = "${method.name}($params): ${method.returnType.simpleName}"
                        XposedBridge.log("SecurityBypassHook: [扫描]   $sig")

                        // hook 无参方法，追踪运行时调用
                        if (method.parameterTypes.isEmpty()) {
                            try {
                                XposedBridge.hookMethod(method, object : XC_MethodHook() {
                                    override fun beforeHookedMethod(param: MethodHookParam) {
                                        XposedBridge.log("SecurityBypassHook: [探测] ${cls.name}.${method.name}() 被调用")
                                    }
                                })
                            } catch (_: Throwable) { }
                        }
                    }
                } catch (e: Throwable) {
                    XposedBridge.log("SecurityBypassHook: [扫描] 加载 $className 失败: ${e.message}")
                }
            }
        } catch (e: Throwable) {
            XposedBridge.log("SecurityBypassHook: [扫描] 执行失败: ${e.message}")
        }
    }
}
