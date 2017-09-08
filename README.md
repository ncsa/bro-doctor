
# Bro Doctor

This plugin provides a "doctor.bro" command for broctl that will help to
troubleshoot various common cluster problems.

This plugin runs the following checks:
## check_SAD_connections
Checks if many recent connections have a SAD or had history

## check_capture_loss
Checks for recent capture_loss.log entries

## check_duplicate_5_tuples
Checks if any recent connections have been logged multiple times

## check_pfring
Checks if bro is linked against pf_ring if lb_method is pf_ring

## check_reporter
Checks for recent reporter.log entries


# Usage

    broctl doctor.bro [check] [check]

## Examples
Run all checks

    broctl doctor.bro

Run just the duplicate check

    broctl doctor.bro check_duplicate_5_tuples


