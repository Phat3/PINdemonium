
import os
from distutils.core import setup, Extension
from distutils.sysconfig import get_python_inc

incdir = os.path.join(get_python_inc(plat_specific=1))

module = Extension('pydasm',
	include_dirs = [incdir],
	libraries = [],
	library_dirs = [],
	sources = ['../libdasm.c', 'pydasm.c'])

setup(name = 'pydasm',
    version = '1.5',
    description = 'Python module wrapping libdasm',
    author = 'Ero Carrera',
    author_email = 'ero@dkbza.org',
    ext_modules = [module])
