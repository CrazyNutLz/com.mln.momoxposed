package com.mln.momoxposed.util

import android.content.Context

/** hook 发现结果的数据载体 */
data class HookData(
    val wordLimitClass: String,    // 单词上限类名
    val wordLimitMethod: String,   // 单词上限方法名
    val userLevelClass: String,    // 用户等级类名
    val userLevelMethod: String    // 用户等级方法名
)

/**
 * hook 数据缓存管理
 * 使用 SharedPreferences 持久化已发现的类名和方法名，避免每次启动都重新扫描
 * 缓存与目标应用的 versionCode 绑定，版本更新后自动失效
 */
object HookCache {

    private const val PREFS_NAME = "momo_hook_cache"
    private const val KEY_WORD_LIMIT_CLASS = "word_limit_class"
    private const val KEY_WORD_LIMIT_METHOD = "word_limit_method"
    private const val KEY_USER_LEVEL_CLASS = "user_level_class"
    private const val KEY_USER_LEVEL_METHOD = "user_level_method"
    private const val KEY_VERSION_CODE = "version_code"

    /**
     * 加载缓存的 hook 数据
     * @return 缓存有效时返回 HookData，否则返回 null
     */
    fun load(context: Context, currentVersionCode: Int): HookData? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        // 版本号不匹配则缓存失效
        val savedVersion = prefs.getInt(KEY_VERSION_CODE, 0)
        if (savedVersion != currentVersionCode) return null

        val wordLimitClass = prefs.getString(KEY_WORD_LIMIT_CLASS, "").orEmpty()
        val wordLimitMethod = prefs.getString(KEY_WORD_LIMIT_METHOD, "").orEmpty()
        val userLevelClass = prefs.getString(KEY_USER_LEVEL_CLASS, "").orEmpty()
        val userLevelMethod = prefs.getString(KEY_USER_LEVEL_METHOD, "").orEmpty()

        // 单词上限是必要数据，缺失则视为无效
        if (wordLimitClass.isEmpty() || wordLimitMethod.isEmpty()) return null
        return HookData(wordLimitClass, wordLimitMethod, userLevelClass, userLevelMethod)
    }

    /** 保存 hook 数据到 SharedPreferences（链式单次提交） */
    fun save(context: Context, data: HookData, versionCode: Int) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_WORD_LIMIT_CLASS, data.wordLimitClass)
            .putString(KEY_WORD_LIMIT_METHOD, data.wordLimitMethod)
            .putString(KEY_USER_LEVEL_CLASS, data.userLevelClass)
            .putString(KEY_USER_LEVEL_METHOD, data.userLevelMethod)
            .putInt(KEY_VERSION_CODE, versionCode)
            .apply()
    }
}
