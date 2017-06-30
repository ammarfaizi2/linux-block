#!/usr/bin/perl
#
# This script filters out branchs which should not be
# reported by the tip-bot
#
for (<>) {
    chomp;
    next if (/^\s*(\#.*|)$/);
    next if (/^linus$/);
    next if (/^build$/);
    next if (/^auto-/);
    next if (/^tmp-/);
    next if (/^[^\/]+\/base-/);
    next if (/^rt\//);		# Requested by tglx 2009-07-29
    next if (/^test\// && !/^test\/(tip-bot)$/);
    next if (/^tracing\// && !/^tracing\/(core|urgent)$/);
    print $_, "\n";
}
