#SPDX-License-Identifier: GPL-2.0

import sys

if __name__ == '__main__':
    sys.exit(main(sys.argv))

def main(args):
    if not args:
        print("No tests to run -- did you mean 'make run_x86_tests'?", file=sys.stderr)
        return 0
