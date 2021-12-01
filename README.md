# Sync Threat Response Incidents with 3rd Party 

Notes on how to sync the incidents created in SecureX Threat Response with a 3rd party incident / ticketing system. This is intended as a basic starting point. There are many more details to flush out in a production system.

## Future Additions

The following are topics that can / should be added to this document

1. Fetching assignee information
2. Incident CRUD
3. Using External IDs to tag and retrieve Incidents

## Upcoming Changes

- > Going forward we would like to discourage the use of CTIA (Private Intel) directly in favor of using our new Private Intel IROH service
  
  - This service is not currently available or documented
  - No ETA has been provided for when this service will be made available

## How are Incidents Created?

### Manually by a user in the UI

A user can manually create an incident in the UI. 

### Manually or Automatically by a user / users product via the API

A user can manually or automatically create an incident via the API based a triggering criteria

3rd party products can manually or automatically create an incident via the API based a triggering criteria

### Secure Endpoint Module

The latest (upcoming as of November 30, 2021) version of the Secure Endpoint SecureX Module will created incidents based on "high impact" alerts / events. The configuration of the module will be done from the Secure Endpoint console, it will create enable the module in SecureX and process the events and push incidents to Private Intel

### Firepower Events

Firepower creates Incidents via the API by way of SSE**

**Not entirely clear on the exact data flow for this

### Stealthwatch High Impact Alerts

High impact alerts from built in rules can create incidents

Custom alerts built by the user will not result in incidents regardless of the impact

### SecureX Orchestration Workflows

There are Orchestration Workflows an organization can implement that will create incidents from events generated in products

#### Secure Endpoint

- [Threat Detected Events to Incidents](https://ciscosecurity.github.io/sxo-05-security-workflows/workflows/secure-endpoint/0026-threat-detected-to-incident)
- [Threat Hunting Events to Incidents](https://ciscosecurity.github.io/sxo-05-security-workflows/workflows/secure-endpoint/0012-threat-hunting-to-incidents)
- [Vulnerabilities to SecureX Incidents](https://ciscosecurity.github.io/sxo-05-security-workflows/workflows/secure-endpoint/0022-vulnerabilities-to-incidents)

#### **Umbrella**

- [Excessive Requests to Incidents](https://ciscosecurity.github.io/sxo-05-security-workflows/workflows/umbrella/0023-excessive-requests-to-incident)

## Technical Resources

### Documentation

- SecureX and Threat Response API (These two pages have roughly the same information)
  - [SecureX API Documentation](https://securex.us.security.cisco.com/help/securex/topic/integration)
  - [Threat Response API Documentation](https://visibility.amp.cisco.com/help/integration)

- [Regional Cloud Hosts](https://visibility.amp.cisco.com/clouds.json) - List of the URLs for SecureX services in each region (Asia, Europe, North America)
- [OAuth2 API](https://visibility.amp.cisco.com/iroh/oauth2/index.html) - Used for authentication
- [Inspect API](https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html) - Used to parse strings and automatically extract supported observables and create valid payloads for other APIs
- [Enrich API ](https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html) - Used to query for [CTIM entities](https://github.com/threatgrid/ctim/tree/master/doc#models): [Judgements](https://github.com/threatgrid/ctim/blob/master/doc/structures/judgement.md), [Verdicts](https://github.com/threatgrid/ctim/blob/master/doc/structures/verdict.md), [Sightings](https://github.com/threatgrid/ctim/blob/master/doc/structures/sighting.md), [Indicators](https://github.com/threatgrid/ctim/blob/master/doc/structures/indicator.md), etc...
- [Private Intel Open API Spec](https://private.intel.amp.cisco.com/index.html#/Incident) - This is the API used to interact with [Incidents](https://github.com/threatgrid/ctim/blob/master/doc/structures/incident.md) and [Casebooks](https://github.com/threatgrid/ctim/blob/master/doc/structures/casebook.md)
- [Cisco Threat Intel Model (CTIM)](https://github.com/threatgrid/ctim/tree/master/doc) - SecureX / Threat Response only understand CTIM which is effectively a simplified and slightly tweaked version of STIXv2.

### API Module

A Python Module has been created and is avaialble on [PyPI](https://pypi.org/project/threatresponse/) and [GitHub](https://github.com/CiscoSecurity/tr-05-api-module)

- [Threat Response API Module](https://pypi.org/project/threatresponse/)

### Test Observables

These resources provide public lists of observables (IPs, Domains, URLs, Hashes) that may return Judgements or Verdicts during an investigation

- [AbuseIPDB](https://www.abuseipdb.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/browse/)
- [Pulsedive](https://pulsedive.com/explore/indicators)
- [Snort IP Blocklist](https://snort.org/downloads/ip-block-list)
- [URLhaus](https://urlhaus.abuse.ch/browse/)

### Authentication

Authentication to the SecureX APIs is done via OAuth2. The most direct method is by using the [Client Credential Flow](https://auth0.com/docs/authorization/flows/client-credentials-flow). The [Authorization Code Flow](https://auth0.com/docs/authorization/flows/authorization-code-flow) is supported as well but requires additional setup.

1. Authentication for the Auth Token is done using basic authentication [POST /iroh/oauth2/token](https://visibility.amp.cisco.com/iroh/oauth2/index.html#/OAuth2/post_iroh_oauth2_token)
2. SecureX APIs ([Inspect](https://visibility.amp.cisco.com/iroh/iroh-inspect/index.html), [Enrich](https://visibility.amp.cisco.com/iroh/iroh-enrich/index.html), [Private Intel](https://private.intel.amp.cisco.com/index.html), etc...) use the `access_token` as an `Authorization: Bearer` token in the header

### Rate Limits

In general the rate limits for the SecureX APIs are 8,000 queries per hour and can be checked with the `X-Ratelimit-Org-Limit` header. This is specified in both the [SecureX API Help](https://securex.us.security.cisco.com/help/securex/topic/integration) and the [Threat Response API Help](https://visibility.amp.cisco.com/help/integration) documentation

For Private Intel and Global Intel the header is: `X-Ratelimit-Group-Limit`

This is only documented in the CTIA README on GitHub

https://github.com/threatgrid/ctia/blob/43ff86881b099bfd5a86f6a24a7ec0e05e980c04/README.md#rate-limit

As of November 29, 2021 the rate limit for CTIA queries (Private and Global Intel) is 16,000 queries per hour and is not documented anywhere

### Pagination

Pagination can be accomplished using [Offset Pagination](https://github.com/threatgrid/ctia/blob/43ff86881b099bfd5a86f6a24a7ec0e05e980c04/README.md#offset-pagination), for up to 10,000 results, or [Stateless Cursor Pagination](https://github.com/threatgrid/ctia/blob/43ff86881b099bfd5a86f6a24a7ec0e05e980c04/README.md#stateless-cursor-pagination)

[Stateless Cursor Pagination](https://github.com/threatgrid/ctia/blob/43ff86881b099bfd5a86f6a24a7ec0e05e980c04/README.md#stateless-cursor-pagination) is the recommended method for pagination

## Implementation

### Requirements

1. Regional Host
   - There are currently 3 regions (Asia, Europe, North America) with distinct hosts
   - A list of hosts for each region can be found here: https://visibility.amp.cisco.com/clouds.json
2. API Client ID with `private-intel` scope
3. API Client password

### Communication Flow

#### Authentication

1.  [POST /iroh/oauth2/token](https://visibility.amp.cisco.com/iroh/oauth2/index.html#/OAuth2/post_iroh_oauth2_token)

   1. Client ID and Client Password used for basic auth

   2. grant_type: client_credentials

   3. Response:

      ```json
      {
        "access_token":"eyJhbGciO...",
        "token_type":"bearer",
        "expires_in":600,
        "scope":"enrich:read casebook inspect:read"
      }
      ```

   4. Store the value of `.access_token` to be used as the Authorization Bearer for subsequent queries

#### Collecting Incidents

1. [GET /ctia/incident/search](https://private.intel.amp.cisco.com/index.html#/Incident/get_ctia_incident_search) to get incidents
   1. Use the `sort_by=timestamp`  query parameter to make sure results are returned in chronological order and the `search_after` parameter in the `X-Next` response header is based on time instead of `id` which is a pseudo random value returned alphabetically
   2. Paginate through responses and store incident IDs `.[].id`
   3. Store the value of the `X-Sort` header as the bookmark to be used as the `search_after` value in subsequent queries

#### Collecting Incident Context (Sightings, Observables, Linked References, etc)

1. [POST /ctia/bundle/export](https://private.intel.amp.cisco.com/index.html#/Bundle/post_ctia_bundle_export) to get all associated data (Sightings, Indicators, etc...)
   1. Use the `include_related_entities=true` query parameter to fetch the Incident as well as all associated [CTIM entities](https://github.com/threatgrid/ctim/tree/master/doc#models)
   2. The [resulting output](#bundle-export) can be parsed to provide context about the observablse associated with the Incident. The [Relationships](https://github.com/threatgrid/ctim/blob/master/doc/structures/relationship.md) must be used to understand which entities are associated with which [Incidents](https://github.com/threatgrid/ctim/blob/master/doc/structures/incident.md). Observables (IPs, Domains, Hashes, etc) are not first class objects and live within  [Judgements](https://github.com/threatgrid/ctim/blob/master/doc/structures/judgement.md), [Verdicts](https://github.com/threatgrid/ctim/blob/master/doc/structures/verdict.md), [Sightings](https://github.com/threatgrid/ctim/blob/master/doc/structures/sighting.md), and [Casebooks](https://github.com/threatgrid/ctim/blob/master/doc/structures/casebook.md)

#### Updating Collected Incidents

Updating collected Incidents can be done one of two ways.

1. Query for all incidents in the organization and compare the results against what has already been collected. This methodology would use the same query as the [Collecting Incidents](#collecting-incidents) method with no `search_after` parameter set. The `timestamp` value as defined in the [Incident documentation](https://github.com/threatgrid/ctim/blob/master/doc/structures/incident.md#incident-object):

   > The time this object was created at, or last modified.

   Is not accurate as it is never changed when the Incident is modified and appears to always keep the timestamp the incident object was created

2. Fetch each incident by ID and compare the results against what has already been collected

   1. [GET /ctia/incident/{id}](https://private.intel.amp.cisco.com/index.html#/Incident/get_ctia_incident__id_)

## Gotchas

### Pagination Gotchas

1. You must specify the `sort_by` query parameter in every query

   1. Without the `sort_by` parameter the `X-Next` header returns query parameters with `search_after` present 3 times

      - ```
        limit=25&offset=25&search_after=1637680112997&search_after=1637680112997&search_after=incident-76a813e7-403b-4901-a256-6794f62b7dfe
        ```

2. Without specifying `sort_by` the API defaults to `id` which is the generated (often random) UUID: `incident-76a813e7-403b-4901-a256-6794f62b7dfe`. This causes the response to be returned sorted alphabetically by the random UUID and has no bearing on when the incident was created or updated

3. The [CTIA documentation](https://github.com/threatgrid/ctia/blob/43ff86881b099bfd5a86f6a24a7ec0e05e980c04/README.md#list-pagination) lists several headers that are returned when a limit parameter is used, the `X-PREVIOUS` header is never returned.

### Incident Gotchas

1. Most if not all automatically created Incidents are created from single events, there is little to not logic or correlation that goes into creating the incident. The result is "security events" are promoted to "security incidents" automatically creating a flood of unconfirmed incidents

### Timestamp Gotchas

1. The `timestamp` value as defined in the [Incident documentation](https://github.com/threatgrid/ctim/blob/master/doc/structures/incident.md#incident-object):

   > The time this object was created at, or last modified.

   Is not accurate as it is never changed when the Incident is modified and appears to always keep the timestamp the incident object was created

## Output Examples

Example JSON blobs returned from API queries. The JSON is returned as a single line from the API the output has been expanded and formatted for readability

### Incident Search

**[GET /ctia/incident/search](https://private.intel.amp.cisco.com/index.html#/Incident/get_ctia_incident_search)**

```json
[
  {
    "description": "Description of the new incident being created is shown in the Summary tab",
    "schema_version": "1.1.3",
    "type": "incident",
    "short_description": "This is a test incident short description that is shown in the Description field on the Incidents page",
    "title": "New Incident 95",
    "incident_time": {
      "opened": "2020-07-07T01:01:01.000Z"
    },
    "status": "New",
    "id": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-5fe3d6a4-1a60-4ebd-87e6-da1367b9164e",
    "tlp": "amber",
    "groups": [
      "f1631ad1-316b-438c-a055-631a63f8b6f6"
    ],
    "timestamp": "2021-11-23T15:09:24.155Z",
    "confidence": "High",
    "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
  },
  {
    "description": "Description of the new incident being created is shown in the Summary tab",
    "schema_version": "1.1.3",
    "type": "incident",
    "short_description": "This is a test incident short description that is shown in the Description field on the Incidents page",
    "title": "New Incident 96",
    "incident_time": {
      "opened": "2020-07-07T01:01:01.000Z"
    },
    "status": "New",
    "id": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-ea7bcb6b-3fde-435e-9346-6d7066907fd5",
    "tlp": "amber",
    "groups": [
      "f1631ad1-316b-438c-a055-631a63f8b6f6"
    ],
    "timestamp": "2021-11-23T15:09:24.304Z",
    "confidence": "High",
    "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
  },
  {
    "description": "Description of the new incident being created is shown in the Summary tab",
    "schema_version": "1.1.3",
    "type": "incident",
    "external_ids": [
      "incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94"
    ],
    "short_description": "This is a test incident short description that is shown in the Description field on the Incidents page",
    "title": "New Incident Title",
    "incident_time": {
      "opened": "2020-07-07T01:01:01.000Z"
    },
    "status": "New",
    "id": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95",
    "tlp": "amber",
    "groups": [
      "f1631ad1-316b-438c-a055-631a63f8b6f6"
    ],
    "timestamp": "2021-11-23T14:57:08.986Z",
    "confidence": "High",
    "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
  }
]
```

### Bundle Export

**[POST /ctia/bundle/export](https://private.intel.amp.cisco.com/index.html#/Bundle/post_ctia_bundle_export)**

This output is for a single Incident in the Payload. The ID of the Incident is: `https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95`

```json
{
  "type": "bundle",
  "incidents": [
    {
      "description": "Description of the new incident being created is shown in the Summary tab",
      "schema_version": "1.1.3",
      "type": "incident",
      "external_ids": [
        "incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94"
      ],
      "short_description": "This is a test incident short description that is shown in the Description field on the Incidents page",
      "title": "New Incident Title",
      "incident_time": {
        "opened": "2020-07-07T01:01:01.000Z"
      },
      "status": "New",
      "id": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-23T14:57:08.986Z",
      "confidence": "High",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
    }
  ],
  "source": "ctia",
  "indicators": [
    {
      "description": "Doc.Downloader.Donoff::100.sbx.tg",
      "tags": [
        "malware"
      ],
      "valid_time": {
        "start_time": "2021-11-23T14:57:07.968Z",
        "end_time": "2525-01-01T00:00:00.000Z"
      },
      "producer": "Incident Demo",
      "schema_version": "1.1.3",
      "type": "indicator",
      "external_ids": [
        "incident-demo-indicator-8a3011cd-1774-4008-8080-9bd65e4a71f0"
      ],
      "short_description": "Doc.Downloader.Donoff::100.sbx.tg",
      "title": "Doc.Downloader.Donoff::100.sbx.tg",
      "id": "https://private.intel.amp.cisco.com:443/ctia/indicator/indicator-b413c9fb-8a79-4f9f-a2c9-c8968560451a",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-23T14:57:07.968Z",
      "confidence": "High",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
    }
  ],
  "relationships": [
    {
      "schema_version": "1.1.3",
      "target_ref": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95",
      "type": "relationship",
      "external_ids": [
        "incident-demo-c22a4269ae07827cb1c3ab8ebdbdbd5b722bd2e52afdecc8b5dd1a76b6289323"
      ],
      "source_ref": "https://private.intel.amp.cisco.com:443/ctia/sighting/sighting-b252ea80-ea34-4e9e-9334-a6e6601e06a7",
      "id": "https://private.intel.amp.cisco.com:443/ctia/relationship/relationship-6cd9b1c8-678b-40c6-857c-9ae5f94e133f",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-23T14:57:10.735Z",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8",
      "relationship_type": "member-of"
    },
    {
      "schema_version": "1.1.3",
      "target_ref": "https://private.intel.amp.cisco.com:443/ctia/indicator/indicator-b413c9fb-8a79-4f9f-a2c9-c8968560451a",
      "type": "relationship",
      "external_ids": [
        "incident-demo-a08e3a6eebee24a5d1233a19eb8d15952b2fbf7309fc8f5d8476f8932534b5a7"
      ],
      "source_ref": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95",
      "id": "https://private.intel.amp.cisco.com:443/ctia/relationship/relationship-638e7f94-0d9e-423a-a58c-b259a3bcd0a8",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-23T14:57:10.734Z",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8",
      "relationship_type": "sighting-of"
    },
    {
      "schema_version": "1.1.3",
      "target_ref": "https://private.intel.amp.cisco.com:443/ctia/incident/incident-0a55b5e4-99e2-4dbc-9d45-2efd1855ea95",
      "type": "relationship",
      "source_ref": "https://private.intel.amp.cisco.com:443/ctia/casebook/casebook-01f7e01b-108e-405e-a50d-91f1bcd5c167",
      "id": "https://private.intel.amp.cisco.com:443/ctia/relationship/relationship-5a93caa8-086a-443d-b4fa-19d105b8c31d",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-29T19:58:14.682Z",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8",
      "relationship_type": "related-to"
    }
  ],
  "sightings": [
    {
      "description": "Sighting Description goes in the Description Column",
      "schema_version": "1.1.3",
      "relations": [
        {
          "origin": "Incident Demo",
          "relation": "Downloaded_From",
          "source": {
            "value": "10281a188a26dbb10562bdc6f5467abad4b0e7fe73672b48a11fdd55819f81f3",
            "type": "sha256"
          },
          "related": {
            "value": "112.121.153.187",
            "type": "ip"
          }
        }
      ],
      "observables": [
        {
          "value": "10281a188a26dbb10562bdc6f5467abad4b0e7fe73672b48a11fdd55819f81f3",
          "type": "sha256"
        }
      ],
      "type": "sighting",
      "source": "Incident Demo",
      "external_ids": [
        "incident-demo-sighting-9a4b33d5-abad-4c80-9f46-30ed3206a53c"
      ],
      "targets": [
        {
          "type": "endpoint",
          "observables": [
            {
              "value": "10.10.10.10",
              "type": "ip"
            },
            {
              "value": "Win10-Host01",
              "type": "hostname"
            },
            {
              "value": "00:0c:29:38:21:f6",
              "type": "mac_address"
            }
          ],
          "observed_time": {
            "start_time": "2020-07-06T13:31:17.245Z"
          }
        }
      ],
      "internal": true,
      "source_uri": "https://example.com",
      "id": "https://private.intel.amp.cisco.com:443/ctia/sighting/sighting-b252ea80-ea34-4e9e-9334-a6e6601e06a7",
      "count": 1,
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-23T14:57:09.908Z",
      "confidence": "High",
      "observed_time": {
        "start_time": "2020-07-06T13:31:17.245Z"
      },
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8",
      "sensor": "Network Sensor"
    }
  ],
  "casebooks": [
    {
      "description": "Event 123 from Sentinel",
      "schema_version": "1.1.3",
      "observables": [
        {
          "value": "1.2.3.4",
          "type": "ip"
        }
      ],
      "type": "casebook",
      "short_description": "To be added to New Incident Title Incident",
      "title": "Case for 1.2.3.4",
      "id": "https://private.intel.amp.cisco.com:443/ctia/casebook/casebook-01f7e01b-108e-405e-a50d-91f1bcd5c167",
      "tlp": "amber",
      "groups": [
        "f1631ad1-316b-438c-a055-631a63f8b6f6"
      ],
      "timestamp": "2021-11-29T19:57:12.335Z",
      "owner": "e173c521-5c58-4f90-a850-3097a89cf6b8"
    }
  ]
}
```

