from operator import add
from geoalchemy2.functions import ST_X, ST_Y, ST_Centroid, ST_Distance
from sqlalchemy import exc, func, select, or_, and_
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import joinedload, session
from starlette.routing import request_response

from api.addresses.models import Address
from api.category_collections.categories.models import Categories
from api.category_collections.models import CategoryCollections
from api.database import async_session_maker
from api.pois.models import POI
from api.report.schemas import ReportCreate
from api.pois.dao import POIDAO
from api.exceptions import NotFoundException



class ReportDAO:

    @classmethod
    async def generate_report_create_for_celery(
        cls, report_request: ReportCreate
    ):
        pois = await cls.get_nearest_pois(
            report_request, cls._build_nearest_pois_query
        )
        custom_pois = await cls.get_nearest_pois(
            report_request, cls._build_custom_pois_query
        )

        start_point_data = await cls.get_start_point_information(
            report_request.address_id
        )
        custom_addressess = await cls.get_custom_addresses(report_request)
        return {
            "start_point": start_point_data,
            "pois": pois,
            "custom_pois": custom_pois,
            "custom_addressess": custom_addressess,
            "request": report_request.model_dump()
        }

    @classmethod
    async def get_missing_categories(cls, pois, report_request: ReportCreate):
        found_category_ids = {
            category.id for poi in pois for category in poi.POI.categories
        }
        missing_category_ids = (
            set(report_request.category_ids) - found_category_ids
        )
        async with async_session_maker() as session:
            query = (
                select(Categories).where(
                    Categories.id.in_(missing_category_ids)
                )
            ).options(joinedload(Categories.collection))
            result = await session.execute(query)
            categories = result.scalars().unique().all()
        return cls._organize_missing_categories(categories)

    @classmethod
    def _organize_missing_categories(cls, categories):
        organized_categories = {}
        for category in categories:
            if organized_categories.get(category.collection.title) is None:
                organized_categories[category.collection.title] = {}
            if (
                organized_categories[category.collection.title].get(
                    category.title
                )
                is None
            ):
                organized_categories[category.collection.title][
                    category.title
                ] = []
        return organized_categories

    @classmethod
    async def _build_nearest_pois_query(
        cls, point, report_request: ReportCreate
    ):
        query = (
            select(
                POI,
                ST_X(ST_Centroid(Address.geometry)).label("center_longitude"),
                ST_Y(ST_Centroid(Address.geometry)).label("center_latitude"),
            )
            .join(Address, POI.address_id == Address.id)
            .join(POI.categories)
            .where(Categories.id.in_(report_request.category_ids))
            .where(
                ST_Distance(Address.geometry, point) * 111000
                < report_request.distance
            )
            .options(joinedload(POI.address), joinedload(POI.categories))
        )
        return query

    @classmethod
    async def _build_custom_pois_query(
        cls, point, report_request: ReportCreate
    ):
        async with async_session_maker() as session:
            query = (
                select(POI)
                .where(POI.id.in_(report_request.custom_places_ids))
                .options(joinedload(POI.categories))
            )
            result = await session.execute(query)
            custom_poi_templates = result.scalars().unique().all()
            poi_names = [poi.name for poi in custom_poi_templates]

            base_query = (
                select(
                    POI,
                    ST_X(ST_Centroid(Address.geometry)).label(
                        "center_longitude"
                    ),
                    ST_Y(ST_Centroid(Address.geometry)).label(
                        "center_latitude"
                    ),
                )
                .join(Address, POI.address_id == Address.id)
                .join(POI.categories)
                .where(
                    ST_Distance(Address.geometry, point) * 111000
                    < report_request.distance
                )
                .where(POI.name.in_(poi_names))
                .options(joinedload(POI.address), joinedload(POI.categories))
            )

        return base_query

    @classmethod
    async def get_nearest_pois(
        cls, report_request: ReportCreate, query: callable
    ):
        async with async_session_maker() as session:
            point_dict = await ReportDAO.get_centroid_by_address_id(
                report_request.address_id
            )
            point = await ReportDAO.create_WKE_point(point_dict)
            query = await query(point, report_request)
            result = await session.execute(query)

            pois = result.unique().all()
            return await cls._organize_pois(pois, report_request)

    @classmethod
    async def get_start_point_information(cls, address_id: int):
        start_point = {}
        start_point["location"] = await cls.get_centroid_by_address_id(
            address_id
        )
        start_point["address"] = (
            await ReportDAO.get_address_by_id(address_id)
        ).to_dict()
        return start_point

    @classmethod
    async def _organize_pois(cls, pois, report_request: ReportCreate):
        data = {}

        for poi, lon, lat in pois:
            for category in [category for category in poi.categories]:
                collection_title = category.collection.title
                category_titile = category.title
                if not data.get(collection_title):
                    data[collection_title] = {}
                if not data[collection_title].get(category_titile):
                    data[collection_title][category_titile] = []

                data[collection_title][category_titile].append(
                    {
                        "name": poi.name,
                        "location": {"lat": lat, "lon": lon},
                        "address": poi.address.to_dict(),
                    }
                )
        empty_categories_dict = await cls.get_missing_categories(
            pois, report_request
        )
        data = cls._add_empty_categories_to_pois(data, empty_categories_dict)
        return data

    @classmethod
    def _add_empty_categories_to_pois(
        cls, pois: dict, empty_categories_dict: dict
    ):
        for collection_name, categories in empty_categories_dict.items():
            for category in categories:
                if not pois.get(collection_name):
                    pois[collection_name] = {}
                if not pois[collection_name].get(category):
                    pois[collection_name][category] = []
        return pois

    @classmethod
    async def get_centroid_by_address_id(cls, address_id: int):
        async with async_session_maker() as session:
            query = select(
                Address,
                ST_X(ST_Centroid(Address.geometry)).label("center_longitude"),
                ST_Y(ST_Centroid(Address.geometry)).label("center_latitude"),
            ).where(Address.id == address_id)
            result = await session.execute(query)
            result = result.first()
            if not result:
                raise NotFoundException("Address not found")
            return {
                "lat": result.center_latitude,
                "lon": result.center_longitude,
            }

    @classmethod
    async def get_address_by_id(cls, address_id: int):
        async with async_session_maker() as session:
            query = select(Address).where(Address.id == address_id)
            result = await session.execute(query)
        return result.scalar()

    @classmethod
    async def create_WKE_point(cls, point):
        return func.ST_GeomFromText(
            f"POINT({point.get('lon')} {point.get('lat')})",
            4326,
        )

    @classmethod
    async def get_custom_addresses(cls, report_request: ReportCreate):
        custom_adressess = []
        addressess = [
            await ReportDAO.get_address_by_id(address_id)
            for address_id in report_request.custom_address_ids
        ]
        for address in addressess:
            address_dict = {}
            address_dict.update(address.to_dict())
            address_dict["location"] = await cls.get_centroid_by_address_id(
                address.id
            )
            custom_adressess.append(address_dict)
        return custom_adressess
