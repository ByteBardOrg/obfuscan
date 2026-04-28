// Defanged: javax.script.ScriptEngine.eval on a non-literal argument.
// Kotlin's most common dynamic-exec surface is the JSR-223 ScriptEngine.
import javax.script.ScriptEngineManager

fun runScript(code: String): Any? {
    val engine = ScriptEngineManager().getEngineByName("kotlin")
    return engine.eval(code)
}
