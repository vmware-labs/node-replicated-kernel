# Related Work

Bespin takes inspiration from decades of academic research. The following list
is not exhaustive:

## Operating Systems

## Logs

Logs have been used extensively for simplifying and scaling data-structures,
designing distributed systems and operating systems:

Linearizable operation logs are ubiquitous in distributed systems. For example,
many protocols such as Raft~\cite{raft-atc14}, Corfu~\cite{corfu-osr17} and
Delos~\cite{delos} use a log to simplify reaching consensus and fault-tolerance,
as well as to scale out a single-node implementation to multiple machines.
Recently, the same abstraction has been used to achieve good scalability on
large machines both in file systems~\cite{scaleFS-sosp17} and general data
structures~\cite{Hendler:2010, Matveev:2015, mvrlu, predictive-log, oplog}.

## Scalable Data structures

## Replication

