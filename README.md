
# Bro Doctor

This plugin provides a "doctor.bro" command for broctl that will help to
troubleshoot various common cluster problems.

This plugin runs the following checks:
## check_SAD_connections
Checks if many recent connections have a SAD or had history

If any connections have a history that is one sided (all uppercase or all lowercase)
this indicates that bro is only seeing half of the connection.

## check_capture_loss
Checks for recent capture_loss.log entries

Capture loss should be as low as possible across all workers.

## check_capture_loss_conn_pct
Checks what percentage of recent tcp connections show loss

Like capture loss, but instead of reporting on the absolute loss amount,
report on the percentage of recent connections show any loss at all.

## check_deprecated_scripts
Checks if anything is in the deprecated local-logger.bro, local-manager.bro, local-proxy.bro, or local-worker.bro scripts

Unless you know what you are doing, you should ONLY be using local.bro.

## check_duplicate_5_tuples
Checks if any recent connections have been logged multiple times

Each connection should only be logged once.  If a connection is logged multiple times,
especially once per worker, load balancing is not working properly.

## check_connection_distribution
Checks if connections are unevenly distributed across workers

Usually, connections should be distributed evenly across workers. If connections are
unevenly distributed, load balancing might be not working properly.

## check_local_connections
Checks what percentage of recent tcp connections are remote to remote.

This will detect problems with networks.cfg not listing all subnets that should be
considered local.

## check_malloc
Checks if bro is linked against a custom malloc like tcmalloc or jemalloc

Bro performs best when using a better malloc than the standard one in glibc.

## check_pfring
Checks if bro is linked against pf_ring if lb_method is pf_ring

If bro is configured to use pf_ring, it needs to be linked against it.
If bro is linked against pf_ring, it should be using it.

## check_reporter
Checks for recent reporter.log entries

If bro is running well, there will be zero reporter.log messages.


# Usage

    broctl doctor.bro [check] [check]

## Examples
Run all checks

    broctl doctor.bro

Run just the duplicate check

    broctl doctor.bro check_duplicate_5_tuples


