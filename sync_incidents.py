import os

from urllib.parse import parse_qsl

import threatresponse
from threatresponse import ThreatResponse


def read_x_sort_header() -> int:
    """Read the search_after bookmark from the search_after file located
    in the directory the script is located in"""
    abs_path = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(f"{abs_path}/search_after", "r", encoding="utf-8") as file:
            return int(file.read())
    except FileNotFoundError:
        return None


def store_x_sort_header(response_obj: threatresponse.request.response.Response) -> None:
    """Write the x-sort bookmark into the search_after file located
    in the directory the script is located in. The value is returned
    as a string between brackets [] which must be stripped off"""
    x_sort = response_obj.headers.get("x-sort")
    abs_path = os.path.dirname(os.path.abspath(__file__))
    if x_sort:
        with open(f"{abs_path}/search_after", "w", encoding="utf-8") as file:
            file.write(x_sort[1:-1])


def append_ids(
    ids: list, response_obj: threatresponse.request.response.Response
) -> None:
    """Parse Threat Response Response Object for CTIM object IDs and append to the provided list"""
    for incident in response_obj.json():
        uuid = incident.get("id")
        ids.append(uuid)


def get_incident_ids(
    client: threatresponse.client.ThreatResponse, search_after=None
) -> list:
    """Query Threat Response Private Intel for Incidents starting from the
    search_after bookmark if provided. Paginate through results if required
    and parse each page into a list of Incident IDs"""
    params = {
        "sort_order": "asc",
        # Explicitly list Incidents on page from oldest to newest
        "sort_by": "timestamp",
        # If excluded `id` is used, this results in pseudo random ids being sorted
        # alphabetically which makes no sense. This field also determines what field
        # is used in the `search_after` parameter
    }

    if search_after:
        params["search_after"] = search_after

    response = client.private_intel.incident.search.get(
        params=params, response_type="raw"
    )

    ids = []
    append_ids(ids, response)

    while next_params := response.headers.get("x-next"):
        # Combine Starting Params with Next Params updating existing values with Next Params
        params = params | dict(parse_qsl(next_params))
        response = client.private_intel.incident.search.get(
            params=params, response_type="raw"
        )
        append_ids(ids, response)

    store_x_sort_header(response)

    return ids


def get_incident_budles(client: threatresponse.client.ThreatResponse, ids: list):
    """Query Threat Response for Bundles
    Incident Bundles contain all of the CTIM entities associated with the ID of a given object
    Querying for the Incident ID will return all of the Indicators, Sightings, Casebooks, etc...
    that are linked to an Incident"""
    params = {"include_related_entities": "true"}

    payload = {"ids": ids}

    response = client.private_intel.bundle.export.post(
        params=params, payload=payload, response_type="raw"
    )

    return response


def main():
    """Main script logic for fetching SecureX Threat Response Incidents"""

    client = ThreatResponse(
        client_id=os.getenv("CLIENT_ID"),
        client_password=os.getenv("CLIENT_PASSWORD"),
    )

    print("Checking for search_after bookmark")
    search_after = read_x_sort_header()
    if search_after:
        print(f"Search_after bookmark found: {search_after}")
    else:
        print("No search_after bookmark founde, querying for all Incidents")

    print("\nQuerying for Incidents", end=" ")
    incident_ids = get_incident_ids(client, search_after)
    print("- Done!")

    print("Total Indicent IDs:", len(incident_ids))
    print("Tltal Unique Indicent IDs", len(set(incident_ids)))

    print("\nQuerying for Incident Bundles", end=" ")
    incident_bundles = get_incident_budles(client, incident_ids)
    print("- Done!")

    print("\nParsing Bundles")
    ctim_object_types = set(
        key for key in incident_bundles.json() if key not in ("type", "source")
    )
    if ctim_object_types:
        print(f"Retrieved {len(ctim_object_types)} CTIM Entity Types")
        print(ctim_object_types)


if __name__ == "__main__":
    main()
