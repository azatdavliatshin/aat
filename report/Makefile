DRAFT := draft-davliatshin-oauth-attenuation-chains-report
SRC   := $(DRAFT).md
OUT   := $(DRAFT)-00

.PHONY: all idnits clean

all: $(OUT).xml $(OUT).txt $(OUT).html

$(OUT).xml: $(SRC)
	kramdown-rfc $(SRC) > $@.tmp && mv $@.tmp $@

$(OUT).txt: $(OUT).xml
	xml2rfc --text $<

$(OUT).html: $(OUT).xml
	xml2rfc --html $<

idnits: $(OUT).txt
	idnits $<

clean:
	rm -f $(OUT).xml $(OUT).txt $(OUT).html $(OUT).xml.tmp
