# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

po:
	sphinx-build -b gettext . _build/gettext
	/opt/local/Library/Frameworks/Python.framework/Versions/3.8/bin/sphinx-intl update -p _build/gettext -l ja

ja:
	sphinx-build -b html -D language=ja . _build/html/ja

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	echo ".. figure:: docs/mckernel-logo.png" > ../README.rst; echo >> ../README.rst
	cat summary.rst >> ../README.rst; echo >> ../README.rst
	cat doc.rst >> ../README.rst
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
