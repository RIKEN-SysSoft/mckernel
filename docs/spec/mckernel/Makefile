.SUFFIXES:

MAINBN = mckernel

ALLPDF = $(MAINBN).pdf

FIGSPDF = $(shell ls figs/*.pdf)
FIGSEPS = $(shell ls figs/*.eps)
FIGSXBB = $(FIGSPDF:.pdf=.xbb)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
PREVIEW = open -a Preview $*.pdf
endif

HLDIFFWG ?= n
HLDIFFJULTWO ?= n
HLDIFFAUG ?= n
HLDIFFSEP ?= n
HLDIFFMAR ?= n
HLDIFFPREV ?= n
HLDIFFRCF ?= y
OPTS='\let\HLDIFFWG=$(HLDIFFWG) \let\HLDIFFJULTWO=$(HLDIFFJULTWO) \let\HLDIFFAUG=$(HLDIFFAUG) \let\HLDIFFSEP=$(HLDIFFSEP) \let\HLDIFFMAR=$(HLDIFFMAR) \let\HLDIFFPREV=$(HLDIFFPREV) \let\HLDIFFRCF=$(HLDIFFRCF) \input'

all: main

main: $(ALLPDF)

%.xbb: %.pdf
	extractbb $< 

%.aux: %.tex
	platex $(OPTS) $*

%.bbl: %.bib %.aux
	bibtex $*
	platex $(OPTS) $*
	bibtex $* 

$(MAINBN).dvi: $(MAINBN).tex $(FIGSXBB) $(MAINBN).bbl
	platex $(OPTS) $(MAINBN)

%.pdf: %.dvi
	dvipdfmx $<
	$(PREVIEW)

clean:
	rm -f $(ALLPDF) $(FIGSXBB) $(ALLPDF:.pdf=.dvi) $(ALLPDF:.pdf=.aux) $(ALLPDF:.pdf=.glo) $(ALLPDF:.pdf=.gls) $(ALLPDF:.pdf=.glsdefs) $(ALLPDF:.pdf=.toc) $(ALLPDF:.pdf=.out)

#.SECONDARY:
