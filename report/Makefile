DRAFT := draft-davliatshin-oauth-attenuation-chains-analysis
SRC   := $(DRAFT).md

.PHONY: all idnits clean

all: $(DRAFT).xml $(DRAFT).txt $(DRAFT).html

$(DRAFT).xml: $(SRC)
	kramdown-rfc $(SRC) > $@.tmp && mv $@.tmp $@

$(DRAFT).txt: $(DRAFT).xml
	xml2rfc --text $<

$(DRAFT).html: $(DRAFT).xml
	xml2rfc --html $<

idnits: $(DRAFT).txt
	idnits $<

clean:
	rm -f $(DRAFT).xml $(DRAFT).txt $(DRAFT).html $(DRAFT).xml.tmp
