from operator import add
from api.dao import base
import openrouteservice as ors
from celery import shared_task
from geojson import Feature, FeatureCollection, Point
import googlemaps
import datetime
import zlib
import base64
from api.config import config

from hashlib import sha256
from api.config import config
import hmac
import hashlib
import base64
import datetime
import json

def generate_sharable_token(user_id, request):
    request["version"] = 1
    request["generated"] = datetime.datetime.now().timestamp()
    request["user_id"] = user_id
    json_request = json.dumps(request, sort_keys=True)
    signature = hmac.new(config.JWT_SECRET.encode(), json_request.encode(), hashlib.sha256).digest()

    result_compressed = zlib.compress(json_request.encode("ascii"))
    
    url_safe_signature = base64.urlsafe_b64encode(signature).decode()
    result_compressed_url_safe = base64.urlsafe_b64encode(result_compressed).decode()

    return result_compressed_url_safe, url_safe_signature

 

def calc_distance_between_coordinates(from_, to):
    client = ors.Client(key="", base_url=config.ORS_URL)

    coordinates = [from_, to]
    response = client.directions(
        coordinates=coordinates,
        profile="foot-walking",
        format="json",
        validate=False,
    )
    return response.get("routes")[0].get("summary", {}).get("distance", -1)


def _insert_poi_to_features_list(
    features: list, nearest_points_dict, type_: str
):
    for collection_title, categories in nearest_points_dict[type_].items():
        for category_title, pois in categories.items():
            for poi in pois:
                point = Point((poi["location"]["lon"], poi["location"]["lat"]))
                properties = {
                    "name": poi["name"],
                    "address": poi["address"],
                    "category": category_title,
                    "collection": collection_title,
                    "distance": poi["distance"],
                }
                features.append(Feature(geometry=point, properties=properties))


def generate_geojson(nearest_points_dict):
    features = []

    # Add start_point as a GeoJSON feature
    if "start_point" in nearest_points_dict:
        start_point = nearest_points_dict["start_point"]["location"]
        point = Point((start_point["lon"], start_point["lat"]))
        features.append(
            Feature(geometry=point, properties={"name": "Start Point"})
        )

    # Add POIs as GeoJSON features
    if "pois" in nearest_points_dict:
        _insert_poi_to_features_list(features, nearest_points_dict, "pois")
    if "custom_pois" in nearest_points_dict:
        _insert_poi_to_features_list(
            features, nearest_points_dict, "custom_pois"
        )

    # Create GeoJSON FeatureCollection
    geojson_obj = FeatureCollection(features)
    return geojson_obj


def calc_distance_for_all(from_, nearest_pois: dict, key: str):
    for collection, categories in nearest_pois[key].items():
        for category, pois in categories.items():
            i = 0
            for poi in pois:
                to = [
                    poi.get("location", {}).get("lon"),
                    poi.get("location", {}).get("lat"),
                ]
                distance = calc_distance_between_coordinates(from_, to)
                nearest_pois[key][collection][category][i][
                    "distance"
                ] = distance
                i += 1


@shared_task
def generate_report(user_id, nearest_pois: dict):
    from_ = [
        nearest_pois.get("start_point", {}).get("location").get("lon"),
        nearest_pois.get("start_point", {}).get("location").get("lat"),
    ]
    for key in ["pois", "custom_pois"]:
        calc_distance_for_all(from_, nearest_pois, key)

    nearest_pois["custom_addressess"] = calc_time_for_custom_addressess(
        nearest_pois.get("start_point").get("address").get("full_address"),
        nearest_pois.get("custom_addressess"),
    )
    data, signature = generate_sharable_token(user_id, nearest_pois.get("request"))
    return {"full": nearest_pois, "geojson": generate_geojson(nearest_pois), "shareData": data, "signature": signature}


def calc_time_for_custom_addressess(
    start_address: str, custom_addressess: list
):
    gmaps = googlemaps.Client(key=config.GOOGLE_MAPS_API_KEY)
    now = datetime.datetime.now()
    for index, requested_address in enumerate(custom_addressess):
        route = {}
        for mode in ["transit", "bicycling", "walking", "driving"]:
            # TODO: add different time
            directions_result = gmaps.directions(
                start_address,
                requested_address.get("full_address"),
                mode=mode,
                departure_time=now,
            )
            if mode not in route:
                route[mode] = {}
            route[mode]["time"] = (
                directions_result[0]
                .get("legs")[0]
                .get("duration")
                .get("value")
            )
            route[mode]["distance"] = (
                directions_result[0]
                .get("legs")[0]
                .get("distance")
                .get("value")
            )
        custom_addressess[index]["route"] = route
    return custom_addressess
