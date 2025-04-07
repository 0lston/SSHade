
import json

version_json = '''
{"date": "2025-01-23T02:17:34.900722", "dirty": false, "error": null, "full-revisionid": "5f3e3d7b01fac2f389e93fd8d66d09dba076cf8f", "version": "1.1.1"}'''  # END VERSION_JSON


def get_versions():
    return json.loads(version_json)

