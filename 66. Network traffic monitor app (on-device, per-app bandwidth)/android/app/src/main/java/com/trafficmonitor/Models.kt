package com.trafficmonitor

data class AppSample(
    val uid: Int,
    val name: String,
    val cat: String,
    val color: Int,
    val rxBps: Long,
    val txBps: Long,
    val conns: Int
) {
    val totalBps: Long get() = rxBps + txBps
}

data class Snapshot(
    val ts: Long,
    val totalRx: Long,
    val totalTx: Long,
    val apps: List<AppSample>,
    val mode: String
)

data class AppPoint(val rx: Long, val tx: Long)