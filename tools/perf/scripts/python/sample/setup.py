#!/usr/bin/python2

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext as _build_ext
from os import getenv

srctree = getenv('srctree')
include = [
            '%s/tools/perf/util' % (srctree),
            '%s/tools/include' % (srctree),
            '%s/tools/perf/scripts/python/sample' % srctree
          ]

build_dir = getenv('PYTHON_SAMPLE_BUILD')
build_lib = '%s/lib' % build_dir
build_tmp = '%s/tmp' % build_dir

class build_ext(_build_ext):
    def finalize_options(self):
        _build_ext.finalize_options(self)
        self.build_lib  = build_lib
        self.build_tmp  = build_tmp

module = Extension('perfsample', sources = ['scripts/python/sample/perfsample.c'])
setup (name = 'perfsample',
       include_dirs = include,
       version = '1.0',
       description = 'This is a perfsample extension',
       ext_modules = [module],
       cmdclass={'build_ext': build_ext} )
