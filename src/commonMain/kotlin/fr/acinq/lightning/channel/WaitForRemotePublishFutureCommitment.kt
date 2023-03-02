package fr.acinq.lightning.channel

import fr.acinq.lightning.blockchain.BITCOIN_FUNDING_SPENT
import fr.acinq.lightning.blockchain.WatchEventSpent
import fr.acinq.lightning.wire.ChannelReestablish
import fr.acinq.lightning.wire.Error

data class WaitForRemotePublishFutureCommitment(
    override val commitments: Commitments,
    val remoteChannelReestablish: ChannelReestablish
) : ChannelStateWithCommitments() {
    override fun updateCommitments(input: Commitments): ChannelStateWithCommitments = this.copy(commitments = input)

    override fun ChannelContext.processInternal(cmd: ChannelCommand): Pair<ChannelState, List<ChannelAction>> {
        return when {
            cmd is ChannelCommand.WatchReceived && cmd.watch is WatchEventSpent && cmd.watch.event is BITCOIN_FUNDING_SPENT -> handlePotentialForceClose(cmd.watch)
            cmd is ChannelCommand.Disconnected -> Pair(Offline(this@WaitForRemotePublishFutureCommitment), listOf())
            else -> unhandled(cmd)
        }
    }

    override fun ChannelContext.handleLocalError(cmd: ChannelCommand, t: Throwable): Pair<ChannelState, List<ChannelAction>> {
        logger.error(t) { "error on command ${cmd::class.simpleName} in state ${this@WaitForRemotePublishFutureCommitment::class}" }
        val error = Error(channelId, t.message)
        return Pair(Aborted, listOf(ChannelAction.Message.Send(error)))
    }
}
