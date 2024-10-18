from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from api.category_collections.categories.router import get_category_by_id
from api.report.dao import ReportDAO
from api.report.schemas import ReportCreate
from api.tasks.tasks import generate_report
from api.users.models import User
from api.users.user_manager import current_user_optional, current_active_user
from api.users.history.router import create_history_record
from api.exceptions import DuplicateEntryException, NotFoundException
from api.users.limits.router import get_user_limits
from api.users.dao import UserDAO
from hashlib import sha256
from api.config import config
import hmac
import hashlib
import base64
import datetime
import zlib


router = APIRouter(prefix="/report", tags=["Report"])

def decode_sharable_token(sharable_token, sign_token):
    sign_token = base64.urlsafe_b64decode(sign_token)
    sharable_token = zlib.decompress(base64.urlsafe_b64decode(sharable_token)).decode()
    signature = hmac.new(config.JWT_SECRET.encode(), sharable_token.encode(), hashlib.sha256).digest()
    if signature != sign_token:
        raise ValueError("Invalid token")
    version = sharable_token.split("\n")[0]
    user_id = sharable_token.split("\n")[1]
    address_id = sharable_token.split("\n")[2]
    category_ids = sharable_token.split("\n")[3].split(" ")
    custom_address_ids = sharable_token.split("\n")[4].split(" ")
    custom_places_ids = sharable_token.split("\n")[5].split(" ")
    timestamp = sharable_token.split("\n")[6]
    return {
        "user_id": int(user_id),
        "address_id": int(address_id),
        "category_ids": list(map(lambda id_: int(id_), category_ids)),
        "custom_address_ids": list(map(lambda id_: int(id_), custom_address_ids)),
        "custom_places_ids": list(map(lambda id_: int(id_), custom_places_ids)),
        "timestamp": int(timestamp),
    }
    
    



async def is_user_have_requests(user):
    limits = await get_user_limits(user)
    return not (limits.used_report_requests >= limits.allowed_requests_per_day)


class UserSubscriptionLevelIsNotEnough(Exception):
    pass


class IncorrectCategoryID(Exception):
    pass


async def check_is_user_have_permissions_for_categories(
    user: User, report_request: ReportCreate
):
    for category_id in report_request.category_ids:
        category_level = await get_category_by_id(category_id)
        if not category_level:
            raise NotFoundException
        try:
            category_level = category_level.minimum_subscription_level
        except AttributeError:
            raise IncorrectCategoryID
        if category_level > user.subscription_level:
            raise UserSubscriptionLevelIsNotEnough
    return True


async def check_is_user_have_permission_for_custom_addresses(
    user: User, report_request: ReportCreate
):
    if user is None and report_request.custom_address_ids is not None:
        return False
    return True


async def check_user_permission_on_report(
    user: User, report_request: ReportCreate
):
    if not await check_is_user_have_permission_for_custom_addresses(
        user, report_request
    ):
        return False
    return True


@router.post("/", status_code=202, )
async def generate_report_geojson(
    report_request: ReportCreate,
    user: User = Depends(current_active_user),
):
    if not await is_user_have_requests(user):
        raise HTTPException(403, "User exceed daily limit")
    if not await check_user_permission_on_report(user, report_request):
        raise HTTPException(403, "User dont have permission")
    try:
        is_user_have_permission_for_categories = (
            await check_is_user_have_permissions_for_categories(
                user, report_request
            )
        )
    except NotFoundException:
        raise HTTPException(404, "Some categories not found")
    if not is_user_have_permission_for_categories:
        raise HTTPException(403, "User dont have permission on category")
    try:
        nearest_pois_dict = await ReportDAO.generate_report_create_for_celery(
            report_request
        )
    except NotFoundException:
        raise HTTPException(404, "Adress or category not found")
    try:
        await create_history_record(user, nearest_pois_dict)
    except DuplicateEntryException:
        pass


    res = generate_report.delay(user.id,nearest_pois_dict)

    return res.id




@router.get("/sharing")
async def get_task_id_by_sharable_data(sharable_data, signature, user: User = Depends(current_user_optional)):
    try:
        data = decode_sharable_token(sharable_data, signature)
    except ValueError:
        raise HTTPException(404, "Data was modified")
    user = await UserDAO.find_by_id(int(data["user_id"]))
    task_id = await generate_report_geojson(ReportCreate.validate(data), user)
    return task_id

@router.get("/{task_id}", status_code=200)
async def get_task_result(
    task_id: str, request: Request, user: User = Depends(current_user_optional)
):
    result = AsyncResult(task_id)
    accept_header = request.headers.get("accept", "application/json")

    if result.state == "PENDING":
        response_data = {
            "task_id": task_id,
            "status": "Pending",
            "result": None,
        }
        return JSONResponse(content=response_data, status_code=202)
    elif result.state == "FAILURE":
        response_data = {
            "task_id": task_id,
            "status": "Failed",
            "result": str(result.info),
        }
        return JSONResponse(content=response_data, status_code=500)
    elif result.state == "SUCCESS":
        response_data = {
            "task_id": task_id,
            "status": "Success",
            "result": result.result,
        }

        if accept_header == "application/geojson":
            geojson_data = response_data.get("result", {}).get("geojson", {})
            return JSONResponse(content=geojson_data)
        elif accept_header == "application/json":
            json_ = response_data.get("result", {}).get("full", {})
            json_["shareData"] = response_data.get("result", {}).get("shareData")
            json_["signature"] = response_data.get("result", {}).get("signature")
            return JSONResponse(content=json_)
        elif accept_header == "application/json+geojson":
            return JSONResponse(content=response_data)
        else:
            raise HTTPException(422, "Header accept is not set")
    else:
        response_data = {
            "task_id": task_id,
            "status": result.state,
            "result": None,
        }
        return JSONResponse(content=response_data, status_code=202)
