# minemeld-misp
MineMeld nodes for MISP

## Requirements

MineMeld >= 0.9.37b1

## Installation

- in SYSTEM > EXTENSIONS install the extension using git https://github.com/PaloAltoNetworks/minemeld-misp.git
- open a shell on MineMeld and restart the API daemon:

``$ sudo -u minemeld mm-supervisorctl restart minemeld-web``

- refresh your browser

## Miner

To use the Miner you should create a new prototype based on *misp.anyEvent* prototype and add the *url* parameter.

After COMMIT you will be able to specify the authentication key directly from the WebUI.

### Prototype parameters

```yaml
# source name, to identify the origin of the indicators inside MineMeld
source_name: misp.test
# URL of MISP
url: https://misp.example.com
# filters for MISP query
# default: none
# this one check for published events with tag tlp:white
# you can specify a time window of the last N days using datefrom: <N>d
# check the search_index API in PyMISP for available filter parameters
filters:
  published: 1
  tag: 'tlp:white'
  # datefrom: 180d
# select specific inidicator types, default: null (any)
# indicator_types: ['URL', 'IPv4', 'IPv6']
indicator_types: null
# verify remote certificate, default true
verify_cert: true
# require a client certificate, default false
client_cert_required: false
# age out of indicators
age_out:
  sudden_death: true
  default: null
# flag indicators with share level white, if not specified
# by tag
attributes:
  confidence: 70
  # if not specified in the event, default is white for
  # this prototype
  share_leve: white
```
