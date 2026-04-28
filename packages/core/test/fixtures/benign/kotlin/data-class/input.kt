data class User(val id: String, val name: String) {
    val displayName: String
        get() = name.ifBlank { "anonymous" }
}

fun summarize(users: List<User>): String =
    users.joinToString(", ") { it.displayName }
