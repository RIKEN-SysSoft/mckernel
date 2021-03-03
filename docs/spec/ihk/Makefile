TARGETBN = ihk
TEXFILES = ihk.tex glossary.tex
PDFFILES = $(shell ls figs/*.pdf)
XBBFILES = $(PDFFILES:.pdf=.xbb)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
PREVIEW = open -a Preview $(TARGETBN).pdf
endif

HLDIFFOPS ?= n
HLDIFFWG ?= n
HLDIFFJUL ?= n
HLDIFFJULTWO ?= n
HLDIFFAUG ?= n
HLDIFFSEP ?= n
HLDIFFPROC ?= n
HLDIFFPREV ?= n
OPTS='\let\HLDIFFOPS=$(HLDIFFOPS) \let\HLDIFFWG=$(HLDIFFWG) \let\HLDIFFJUL=$(HLDIFFJUL) \let\HLDIFFJULTWO=$(HLDIFFJULTWO) \let\HLDIFFAUG=$(HLDIFFAUG)  \let\HLDIFFSEP=$(HLDIFFSEP) \let\HLDIFFPROC=$(HLDIFFPROC) \let\HLDIFFPREV=$(HLDIFFPREV) \input'

all: $(TARGETBN).pdf

%.xbb : %.pdf
	extractbb $< 

$(TARGETBN).glsdefs: $(TEXFILES) $(XBBFILES) $(PDFFILES)
	platex $(OPTS) $(TARGETBN)

$(TARGETBN).aux : $(TEXFILES) $(TARGETBN).glsdefs $(XBBFILES) $(PDFFILES)
	platex $(OPTS) $(TARGETBN)

# $(TARGETBN).bbl : $(TARGETBN).aux $(TARGETBN).bib $(XBBFILES) $(PDFFILES)
# 	bibtex $(TARGETBN) 
# 	platex $(OPTS) $(TARGETBN)
# 	bibtex $(TARGETBN) 

#$(TARGETBN).glo : $(TARGETBN).glsdefs $(XBBFILES) $(PDFFILES)
#	platex $(OPTS) $(TARGETBN)

$(TARGETBN).gls : $(TARGETBN).glo
	makeglossaries $(TARGETBN)

$(TARGETBN).toc : $(TARGETBN).gls $(XBBFILES) $(PDFFILES)
	platex $(OPTS) $(TARGETBN)

$(TARGETBN).out : $(TARGETBN).toc
	platex $(OPTS) $(TARGETBN)

$(TARGETBN).dvi: $(TARGETBN).aux $(TARGETBN).gls $(TARGETBN).toc $(TARGETBN).out $(XBBFILES) $(PDFFILES)
	platex $(OPTS) $(TARGETBN)

$(TARGETBN).pdf: $(TARGETBN).dvi
	dvipdfmx $(TARGETBN).dvi
	$(PREVIEW)

clean:
	rm -f $(TARGETBN).pdf $(TARGETBN).dvi $(TARGETBN).aux $(TARGETBN).bbl $(TARGETBN).glo $(TARGETBN).gls $(TARGETBN).glsdefs $(TARGETBN).toc $(XBBFILES) $(TARGETBN).out

#.SECONDARY:
