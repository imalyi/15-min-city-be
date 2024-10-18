from api.schemas.global_model import GlobalModelWithJSONAlias
from pydantic import Field


class UserSubscriptionLimit(GlobalModelWithJSONAlias):
    used_report_requests: int = Field(ge=0)
    allowed_requests_per_day: int = Field(ge=0)
#    heatmap_requests: int = Field(ge=0)
#    custom_address_check: int = Field(ge=0)
