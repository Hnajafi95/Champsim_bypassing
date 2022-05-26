# ChampSim
ChampSim is a trace-based simulator for a microarchitecture study.

We integrate ChampSim with C-AMAT parameters to analyze cache performance.

The C-AMAT model can be applied to multicore processors in two ways, single-core measurement, and multicore (single processor) measurement. For the former, we are interested in a single core’s, say core A’s, performance. For the latter, we are interested in the overall multicore performance as a single multicore processor. By the definition of C-AMAT, core A’s C-AMAT can be measured by core A’s number of memory accesses and core A’s memory active cycles. Likewise, the multicore C-AMAT can be measured by the multicore processor’s overall number of accesses and the multicore’s memory active cycles.

In shared LLC, core A’s memory active cycles can be collected by "_active_cycles_per_core"; multicore’s memory active cycles can by collected by "_active_cycles".

# How To
Please read the README.old in detail to know more.
