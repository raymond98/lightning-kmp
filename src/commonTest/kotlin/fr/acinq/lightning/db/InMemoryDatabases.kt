package fr.acinq.lightning.db

/**
 * In-memory implementations of the database components.
 * This should only be used in tests: applications should inject their own implementations depending on the database backend available on the platform.
 */
data class InMemoryDatabases(
    override val channels: InMemoryChannelsDb,
    override val payments: InMemoryPaymentsDb
) : Databases {
    companion object {
        operator fun invoke() = InMemoryDatabases(InMemoryChannelsDb(), InMemoryPaymentsDb())
    }
}