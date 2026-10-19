# report

Source of the implementation and analysis report (Internet-Draft,
Informational, RFC 7942 shape). The source is
`draft-davliatshin-oauth-attenuation-chains-analysis.md` (kramdown-rfc);
`.xml`, `.txt` and `.html` are build products and are not committed.

## Toolchain

Installed on macOS (arm64) with the exact commands below.

| Tool | Version | Install |
|---|---|---|
| kramdown-rfc | 1.7.43 | `gem install connection_pool -v 2.5.5` then `gem install kramdown-rfc` (Ruby 2.7.5; newer `connection_pool` needs Ruby >= 3.2) |
| xml2rfc | 3.34.1 | `pipx install xml2rfc` (puts `xml2rfc` in `~/.local/bin`; run `pipx ensurepath` if it is not on `PATH`) |
| idnits | 3.2.0 | `brew install idnits` |

The first build fetches bibliographic entries for the RFC references from
`bib.ietf.org` into `.refcache/` (ignored), so it needs network access.

## Targets

    make          # .xml (kramdown-rfc), .txt and .html (xml2rfc)
    make idnits   # idnits on the .txt
    make clean
